"""A finished run records each detonation's sandbox run (``run_summary.environment.detonations``).

For every detonation of the job — its own first and each one an agent asked
for — which it is, who asked, the launch text it asked for, the sandbox
provider, how it ended, and what the provider stated of the sandbox run while
the report was in hand: its identifiers, the guest, the sandbox's version,
start and end, whether the sample was run, and the SHA-256 and length of each
raw report part as it was read. The provider is asked through one method
(``SandboxProvider.detonation_facts``); one that does not answer it states
nothing, and what is not stated is "not reported". A job that asked no sandbox
records an empty list.

Every value here is made up for the test.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from malspark.analysis import run_environment
from malspark.analysis.run_environment import (
    ENVIRONMENT_VERSION,
    STATED_ENTRIES,
    STATED_PARTS,
    STATED_READ_CHARS,
    STATED_TEXT_CHARS,
    detonations_record,
    environment_record,
)
from malspark.analysis.run_summary import RunSummaryBuilder
from malspark.core.config import Settings
from malspark.loaders.sandbox_client import report_part
from malspark.providers.base import SandboxProvider
from malspark.providers.detonation import (
    AGENT_ORIGIN,
    DetonationRecord,
    report_facts,
    stated_by,
)
from malspark.tools.capabilities import NOT_REPORTED
from malspark.utils.marked_cut import CUT_MARK
from tests.credential_shapes import lowercase_body, password, prefixed_key

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "sandbox"
NR = NOT_REPORTED
# The facts a provider states, each "not reported" where it does not.
FACT_KEYS = (
    "detonated",
    "task_ids",
    "guest",
    "sandbox_version",
    "sandbox_commit",
    "started",
    "ended",
)
# The analysis machine the CAPE fixture names.
CAPE_GUEST = {"name": "win10", "label": "win10", "platform": "windows", "manager": "KVM"}
# The build the CAPE fixture states (``info.CAPE_current_commit``).
CAPE_COMMIT = "c06696cbb1254b2dd2f3f0ed3a5e726e81484345"


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _facts(**over: Any) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "detonated": True,
        "task_ids": {"/info/id": "19159"},
        "guest": {"name": "win10", "platform": "windows"},
        "sandbox_version": "2.5",
        "sandbox_commit": CAPE_COMMIT,
        "started": "2026-08-13 13:06:05",
        "ended": "2026-08-13 13:09:06",
        "report_parts": [report_part("report", b"{}")],
    }
    facts.update(over)
    return facts


def _record(**over: Any) -> DetonationRecord:
    fields: dict[str, Any] = {
        "provider": "cape2",
        "task_id": "19159",
        "report": {"signatures": []},
        "sandbox_facts": _facts(),
    }
    fields.update(over)
    return DetonationRecord(**fields)


def _held(*records: DetonationRecord) -> Any:
    return SimpleNamespace(detonations=list(records))


# ---------------------------------------------------------------------------
# The record, from built detonations


class TestTheRecord:
    def test_one_detonation_is_one_row_of_every_fact(self) -> None:
        rows = detonations_record(_held(_record()))
        assert rows == [
            {
                "detonation": "d1",
                "origin": "job",
                "provider": "cape2",
                "task_id": "19159",
                "reported": True,
                "detonated": True,
                "task_ids": {"/info/id": "19159"},
                "guest": {"name": "win10", "platform": "windows"},
                "sandbox_version": "2.5",
                "sandbox_commit": CAPE_COMMIT,
                "started": "2026-08-13 13:06:05",
                "ended": "2026-08-13 13:09:06",
                "report_parts": [{"name": "report", "sha256": _sha(b"{}"), "bytes": 2}],
            }
        ]

    def test_three_detonations_with_their_launches_and_one_that_failed(self) -> None:
        first = _record()
        second = _record(
            ordinal=2,
            origin=AGENT_ORIGIN,
            arguments="--install /quiet",
            requested_by=[
                {"agent": "static", "cited_entries": ["ev_0003"]},
                {"agent": "network", "cited_entries": ["ev_0007"]},
            ],
            launch={"provider": "cape2", "arguments": "--install /quiet", "honoured": True},
            task_id="19160",
            sandbox_facts=_facts(task_ids={"/info/id": "19160"}),
        )
        third = _record(
            ordinal=3,
            origin=AGENT_ORIGIN,
            arguments="-k netsvcs",
            requested_by=[{"agent": "static", "cited_entries": ["ev_0009"]}],
            launch={
                "provider": "cape2",
                "arguments": "-k netsvcs",
                "honoured": False,
                "sent": True,
                "via": "options",
            },
            task_id="19161",
            report=None,
            failure="sandbox task 19161 ended with status 'failed_analysis'",
            sandbox_facts=None,
        )
        rows = detonations_record(_held(first, second, third))
        assert rows is not None
        assert [row["detonation"] for row in rows] == ["d1", "d2", "d3"]
        assert "launched_with" not in rows[0] and "requested_by" not in rows[0]
        assert rows[1]["origin"] == "agent"
        assert rows[1]["requested_by"] == ["static", "network"]
        assert rows[1]["launched_with"] == "--install /quiet"
        assert rows[1]["arguments_honoured"] is True
        assert rows[1]["task_ids"] == {"/info/id": "19160"}
        assert rows[2] == {
            "detonation": "d3",
            "origin": "agent",
            "requested_by": ["static"],
            "launched_with": "-k netsvcs",
            "arguments_honoured": False,
            "arguments_via": "options",
            "provider": "cape2",
            "task_id": "19161",
            "reported": False,
            "failure": "sandbox task 19161 ended with status 'failed_analysis'",
            "detonated": NR,
            "task_ids": NR,
            "guest": NR,
            "sandbox_version": NR,
            "sandbox_commit": NR,
            "started": NR,
            "ended": NR,
            "report_parts": [],
        }

    def test_a_provider_that_states_nothing_is_not_reported_throughout(self) -> None:
        (row,) = detonations_record(_held(_record(sandbox_facts={}))) or []
        for key in FACT_KEYS:
            assert row[key] == NR, key
        # A report was read, and its parts were not stated: not "none read".
        assert row["report_parts"] == NR
        assert row["task_id"] == "19159" and row["reported"] is True

    def test_a_job_that_asked_no_sandbox_records_an_empty_list(self) -> None:
        # Mock mode or no sample file: the job's record holds no provider.
        assert detonations_record(_held(DetonationRecord())) == []
        assert detonations_record(_held()) == []
        assert detonations_record(SimpleNamespace()) is None

    def test_a_submission_that_failed_before_a_provider_was_chosen_is_recorded(self) -> None:
        failed = DetonationRecord(failure="the sample file to submit was not found")
        (row,) = detonations_record(_held(failed)) or []
        assert row["provider"] == NR and row["reported"] is False
        assert row["failure"] == "the sample file to submit was not found"
        assert row["report_parts"] == []

    def test_the_environment_carries_the_rows_and_its_version_moved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(run_environment, "host_facts", lambda: {})
        record = environment_record(_held(_record()))
        assert ENVIRONMENT_VERSION == 3
        assert record == {"v": 3, "detonations": detonations_record(_held(_record()))}
        assert environment_record(_held()) == {"v": 3, "detonations": []}

    def test_a_field_that_cannot_be_read_is_not_reported_and_the_row_stays(self) -> None:
        class _Broken:
            provider = "cape2"
            task_id = "19159"
            reported = True

            @property
            def name(self) -> str:
                raise RuntimeError("broken")

        rows = detonations_record(_held(_Broken(), _record())) or []
        assert len(rows) == 2
        assert rows[0]["detonation"] == NR and rows[0]["origin"] == NR
        assert rows[0]["provider"] == "cape2" and rows[0]["task_id"] == "19159"
        assert rows[0]["reported"] is True and rows[0]["detonated"] == NR
        assert rows[1] == (detonations_record(_held(_record())) or [])[0]

    def test_a_platform_field_that_cannot_be_read_is_left_out_of_the_row(self) -> None:
        class _Raising:
            """Every field the platform fills raises; the identity is readable."""

            name = "d3"
            origin = AGENT_ORIGIN
            provider = "cape2"
            task_id = "19159"
            arguments = ""

            def __getattr__(self, attr: str) -> Any:
                raise RuntimeError(attr)

            @property
            def requested_by(self) -> Any:
                raise RuntimeError("requested_by")

            @property
            def reported(self) -> bool:
                raise RuntimeError("reported")

            @property
            def failure(self) -> str:
                raise RuntimeError("failure")

            @property
            def sandbox_facts(self) -> Any:
                raise RuntimeError("sandbox_facts")

        (row,) = detonations_record(_held(_Raising())) or []
        # No typed field holds the "not reported" string where its type does
        # not allow it: ``requested_by`` (a list), ``reported`` (a boolean) and
        # ``failure`` are left out.
        assert not {"requested_by", "reported", "failure"} & set(row)
        assert row["detonation"] == "d3" and row["provider"] == "cape2"
        assert row["task_id"] == "19159" and row["origin"] == AGENT_ORIGIN
        assert row["detonated"] == NR and row["guest"] == NR

    def test_a_fact_that_cannot_be_read_is_not_reported_beside_the_platform_s_fields(
        self,
    ) -> None:
        class _Unwritable:
            def __str__(self) -> str:
                raise RuntimeError("no text")

        class _UnreadablePart(dict):  # type: ignore[type-arg]
            def get(self, *_: Any) -> Any:
                raise RuntimeError("no part")

        facts = _facts(
            guest={_Unwritable(): "win10"},
            task_ids={_Unwritable(): "19159"},
            report_parts=[_UnreadablePart()],
        )
        record = _record(
            sandbox_facts=facts,
            ordinal=2,
            origin=AGENT_ORIGIN,
            arguments="-k netsvcs",
            requested_by=[{"agent": "static"}],
            launch={"honoured": True},
        )
        (row,) = detonations_record(_held(record)) or []
        # What cannot be read is left out; what was not stated is "not reported".
        assert not {"guest", "task_ids", "report_parts"} & set(row)
        assert row["sandbox_version"] == "2.5" and row["detonated"] is True
        assert row["detonation"] == "d2" and row["requested_by"] == ["static"]
        assert row["launched_with"] == "-k netsvcs" and row["arguments_honoured"] is True
        assert row["provider"] == "cape2" and row["task_id"] == "19159"


# ---------------------------------------------------------------------------
# A hostile launch text, and what no row may carry


HOSTILE = ("a\x00b\x1b[31m\r\n`|<x>{y}‮" * 400)[:5000]


class TestWhatARowCarries:
    def test_a_hostile_launch_text_is_kept_exactly_and_the_summary_holds(self) -> None:
        assert len(HOSTILE) == 5000
        record = _record(
            ordinal=2,
            origin=AGENT_ORIGIN,
            arguments=HOSTILE,
            requested_by=[{"agent": "static"}],
        )
        environment = {"v": ENVIRONMENT_VERSION, "detonations": detonations_record(_held(record))}
        summary = RunSummaryBuilder(start_time=0.0).set_environment(environment).build().to_dict()
        stored = json.loads(json.dumps(summary))
        assert stored["environment"]["detonations"][0]["launched_with"] == HOSTILE
        assert stored["environment"] == environment

    def test_no_credential_signed_url_or_host_path_survives_a_provider_s_words(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.core.paths import OUTSIDE_PROJECT

        key = prefixed_key("ghs_")
        home = str(Path.home())
        signed = f"https://operator:{key}@sandbox.example.org/r?token={key}&X-Amz-Signature={key}"
        facts = {
            "detonated": True,
            "task_ids": {"task": f"{signed}", "path": f"{home}/reports/19159.json"},
            "guest": {"image": f"/var/lib/sandbox/{key}.qcow2"},
            "sandbox_version": signed,
            "started": "x" * 5000,
            "ended": ["not", "a text"],
            "report_parts": [
                {"name": f"{home}/report.json", "sha256": "A" * 64, "bytes": 3},
                {"name": "no digest", "bytes": 3},
                {"name": "a negative length", "sha256": "0" * 64, "bytes": -1},
            ]
            + [{"name": f"p{n}", "sha256": "1" * 64, "bytes": n} for n in range(STATED_PARTS)],
            "url": signed,
        }
        record = _record(sandbox_facts=facts, failure=f"failed reading {home}/x/report.json")
        (row,) = detonations_record(_held(record)) or []
        text = json.dumps(row)
        assert key not in text
        assert home not in text
        assert "/var/lib/sandbox" not in text
        assert OUTSIDE_PROJECT in row["task_ids"]["path"]
        assert "url" not in row
        assert len(row["started"]) <= STATED_TEXT_CHARS
        assert row["ended"] == NR
        assert row["report_parts"][0]["sha256"] == "a" * 64
        assert [p["name"] for p in row["report_parts"][1:3]] == ["p0", "p1"]
        assert len(row["report_parts"]) == STATED_PARTS
        assert row["report_parts_cut"] == "1 more part(s) left out"


class TestAProviderTextIsCutBeforeAnyOtherWork:
    """A long text from a provider costs no more than a short one: it is cut first."""

    def test_a_megabyte_value_and_a_mapping_of_long_values_are_recorded_at_once(self) -> None:
        import time

        big = "A" * 1_000_000
        spaced = "/x " * 333_334
        guest = {
            f"task{n}": {f"key{i}": big for i in range(STATED_ENTRIES)}
            for n in range(STATED_ENTRIES)
        }
        guest[big] = big
        facts = _facts(
            task_ids={f"id{i}": spaced for i in range(STATED_ENTRIES)},
            guest=guest,
            sandbox_version=big,
            started=spaced,
            ended=big,
        )
        record = _record(sandbox_facts=facts, failure=big, provider=big)
        began = time.perf_counter()
        (row,) = detonations_record(_held(record)) or []
        took = time.perf_counter() - began
        # The text read whole took minutes; cut first, it takes milliseconds.
        assert took < 2.0, f"{took:.2f}s"
        for key in ("sandbox_version", "started", "ended", "failure", "provider"):
            assert row[key].endswith(CUT_MARK), key
            assert len(row[key]) <= STATED_TEXT_CHARS, key
        assert len(row["guest"]) == STATED_ENTRIES

    def test_a_word_the_read_ends_inside_is_not_kept(self) -> None:
        # Folded whitespace brings the word the read ends inside into the
        # kept width: half a credential is not one a mask recognises.
        secret = "s3cr3t-value-" * 6
        spaces = "\t" * (STATED_READ_CHARS - 20)
        said = run_environment._said(f"lead {spaces}{secret}")
        assert said == "lead" + CUT_MARK
        assert run_environment._said("word " * 20) == ("word " * 20).strip()

    def test_no_part_of_a_credential_behind_control_characters_survives_the_cut(self) -> None:
        key = prefixed_key("ghs_", 64)
        controls = "\x00" * (STATED_READ_CHARS - len(key) // 2)
        value = controls + key + " tail"
        # Past the read bound whole, behind 600 of them: none of it is read.
        beyond = "\x00" * 600 + key
        facts = _facts(
            sandbox_version=value, guest={value: value}, task_ids={"id": value, "far": beyond}
        )
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        text = json.dumps(row)
        for piece in (key[:8], key[4:12], key[-8:]):
            assert piece not in text, piece
        assert row["sandbox_version"] == CUT_MARK

    def test_no_part_of_one_long_word_survives_the_cut(self) -> None:
        word = lowercase_body(3 * STATED_READ_CHARS)
        assert " " not in word
        (row,) = (
            detonations_record(_held(_record(sandbox_facts=_facts(started=word, guest={word: 1}))))
            or []
        )
        assert word[:16] not in json.dumps(row)
        assert row["started"] == CUT_MARK

    def test_no_part_of_an_address_with_user_info_straddling_the_bound_survives(self) -> None:
        secret = password(40)
        address = f"https://operator:{secret}@sandbox.example.org/report"
        lead = "run at"
        value = lead + " " + "\x07" * (STATED_READ_CHARS - len(lead) - 10) + address
        assert value.index(address) < STATED_READ_CHARS < value.index(address) + len(address)
        (row,) = detonations_record(_held(_record(sandbox_facts=_facts(ended=value)))) or []
        text = json.dumps(row)
        assert secret[:6] not in text and "operator" not in text and "https" not in text
        assert row["ended"] == lead + CUT_MARK


class TestWhatTheSharedScrubMasks:
    """Provider-stated text is masked as the other run-summary rows are: held values and shapes."""

    def test_a_credential_shaped_token_in_a_failure_s_prose_is_masked_in_both_states(self) -> None:
        from malspark.pipeline.events import remember_secret_values

        key = prefixed_key("ghs_")
        for registered in (False, True):
            if registered:
                remember_secret_values([password(20, variant=7)])
            record = _record(failure=f"the sandbox refused {key} as a token")
            (row,) = detonations_record(_held(record)) or []
            for piece in (key, key[:12], key[-12:]):
                assert piece not in json.dumps(row), (registered, piece)

    def test_with_the_registry_populated_an_identifier_reads_as_stated(self) -> None:
        from malspark.pipeline.events import remember_secret_values

        remember_secret_values([password(20, variant=7)])
        # The live-shaped overview's second task, CAPE's commit and a long id.
        long_id = lowercase_body(48)
        image = "win11ltsc2024-20260709-en"
        facts = _facts(
            guest={"behavioral2": {"resource": image, "os": "windows11-ltsc_2024-x64"}},
            task_ids={"/info/id": long_id},
        )
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        assert row["guest"] == facts["guest"]
        assert row["sandbox_commit"] == CAPE_COMMIT
        assert row["task_ids"] == {"/info/id": long_id}

    def test_with_no_registry_a_credential_shaped_identifier_is_masked_and_may_hide_a_name(
        self,
    ) -> None:
        # Fail closed: nothing is known, so an identifier shaped like a
        # credential reads "***" even where it is only an image name.
        key = prefixed_key("ghs_")
        facts = _facts(
            sandbox_version=f"build {key}",
            guest={"image": key, "task": {"image": key}},
            task_ids={"/info/id": key},
            started=key,
        )
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        text = json.dumps(row)
        for piece in (key, key[:12], key[-12:]):
            assert piece not in text, piece
        # A key stays as stated in both states.
        assert list(row["task_ids"]) == ["/info/id"]
        assert (
            detonations_record(
                _held(_record(sandbox_facts=_facts(guest={"image": "win11ltsc2024-20260709-en"})))
            )
            or [{}]
        )[0]["guest"] == {"image": "***"}

    def test_a_registered_value_is_masked_in_an_identity_fact_in_each_encoding(self) -> None:
        from urllib.parse import quote, quote_plus

        from malspark.core import settings_masking
        from malspark.pipeline.events import remember_secret_values

        held = "tidal pool " + lowercase_body(9) + " beacon"
        settings_masking.remember_values([held], scope="job")
        remember_secret_values([held])
        forms = [held, quote_plus(held), quote(held)]
        facts = _facts(
            sandbox_version=f"v {forms[1]}",
            sandbox_commit=forms[2],
            started=forms[0],
            guest={"image": forms[0], forms[1]: "x"},
            task_ids={"id": f"a {forms[0]} b"},
        )
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        text = json.dumps(row)
        for form in forms:
            assert form not in text, form
        assert "tidal" not in text

    def test_a_url_split_across_a_key_and_its_value_is_masked(self) -> None:
        secret = password(24)
        facts = _facts(guest={"https://operator:": f"{secret}@sandbox.example.org/r"})
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        text = json.dumps(row)
        assert secret[:8] not in text and "operator" not in text
        assert row["guest"] == {"***": "***"}

    def test_a_pair_that_hides_nothing_is_kept_as_stated(self) -> None:
        facts = _facts(guest={"/info/id": "win10v2004-20260513-en", "os": "windows10-2004-x64"})
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        assert row["guest"] == facts["guest"]

    def test_a_held_secret_value_with_spaces_is_masked(self) -> None:
        from malspark.pipeline.events import remember_secret_values

        held = "blue harbour " + lowercase_body(10) + " quiet lantern"
        remember_secret_values([held])
        facts = _facts(
            sandbox_version=f"v {held} end", guest={"image": f"x {held}"}, ended=held.upper()
        )
        (row,) = detonations_record(_held(_record(sandbox_facts=facts, failure=held))) or []
        text = json.dumps(row)
        assert held not in text and "blue harbour" not in text and "quiet lantern" not in text
        assert row["sandbox_version"] == "v *** end"

    def test_a_settings_secret_in_an_encoded_form_is_masked(self) -> None:
        from urllib.parse import quote_plus

        from malspark.core import settings_masking

        held = "quiet harbour " + lowercase_body(8) + " lantern"
        settings_masking.remember_values([held], scope="job")
        facts = _facts(sandbox_version=f"v {quote_plus(held)}", guest={"image": held})
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        text = json.dumps(row)
        assert held not in text and quote_plus(held) not in text and "harbour" not in text

    def test_a_mapping_where_a_provider_states_a_start_is_not_reported(self) -> None:
        facts = _facts(started={"behavioral1": "10:01"}, ended={"behavioral1": "10:04"})
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        assert row["started"] == NR and row["ended"] == NR


class _PlugIn:
    """A plug-in provider written before the method: it states nothing."""

    id = "plugin"


class _Failing(_PlugIn):
    def detonation_facts(self, run: Any) -> dict[str, Any]:
        raise RuntimeError("cannot say")


class _OddAnswer(_PlugIn):
    def detonation_facts(self, run: Any) -> Any:
        return ["not", "a", "mapping"]


class TestTheQuestion:
    def test_a_plug_in_without_the_method_states_nothing(self) -> None:
        assert stated_by(_PlugIn(), object()) is None
        assert stated_by(_Failing(), object()) is None
        assert stated_by(_OddAnswer(), object()) is None

    def test_the_contract_s_default_states_nothing(self) -> None:
        assert SandboxProvider.detonation_facts(_PlugIn(), object()) is None  # type: ignore[arg-type]

    def test_a_plug_in_row_is_not_reported_beside_what_the_platform_knows(self) -> None:
        record = _record(provider="plugin", task_id="t-1", sandbox_facts=None)
        (row,) = detonations_record(_held(record)) or []
        assert row["provider"] == "plugin" and row["task_id"] == "t-1"
        assert row["reported"] is True
        for key in FACT_KEYS:
            assert row[key] == NR, key
        assert row["report_parts"] == NR

    def test_no_sandbox_provider_id_is_written_outside_its_module_its_reader_or_the_registry(
        self,
    ) -> None:
        """Covers every module of the packages the record passes through: the
        recorder (``malspark.analysis``'s ``run_environment``), the providers
        (``malspark.providers``, every subpackage), the sandbox clients
        (``malspark.loaders``), the report schemas (``malspark.schemas``) and
        the app's detonation path (``malspark.app``). Left out: each provider's
        own module (``providers/sandbox/<id>.py``, ``loaders/<id>_client.py``,
        ``loaders/<id>_sandbox_client.py``), the format readers
        (``providers/sandbox/readers.py``) and the registry that lists every
        provider's module (``providers/registry.py``). The ids are the
        registry's own list, each written as a quoted literal.
        """
        from malspark.providers import registry

        ids = registry._SANDBOX_MODULES
        root = Path(run_environment.__file__).resolve().parents[1]
        own = {root / "providers" / "sandbox" / f"{name}.py" for name in ids}
        own |= {root / "loaders" / f"{name}_client.py" for name in ids}
        own |= {root / "loaders" / f"{name}_sandbox_client.py" for name in ids}
        left_out = own | {
            root / "providers" / "sandbox" / "readers.py",
            root / "providers" / "registry.py",
        }
        walked = [root / "analysis" / "run_environment.py", root / "app.py"]
        for package in ("providers", "loaders", "schemas"):
            walked += sorted((root / package).rglob("*.py"))
        checked = [module for module in walked if module not in left_out]
        assert len(checked) > 20, len(checked)
        for module in checked:
            text = module.read_text(encoding="utf-8")
            for name in ids:
                for quote in ('"', "'"):
                    assert f"{quote}{name}{quote}" not in text, (str(module), name)


# ---------------------------------------------------------------------------
# Each built-in provider states its run, with the parts as read


class TestEachBuiltInStatesItsRun:
    def test_cape_states_its_info_block_and_the_report_as_fetched(self) -> None:
        from malspark.loaders.cape2_client import CAPEv2Client
        from malspark.providers.sandbox.cape2 import CAPE2SandboxProvider

        body = (FIX / "cape2_report.json").read_bytes()
        client = CAPEv2Client(base_url="http://cape.invalid:8000", api_token="t")
        client._http = httpx.Client(
            base_url="http://cape.invalid:8000",
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=body)),
        )
        provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
        provider._client = client
        run = provider.fetch("19159")
        facts = stated_by(provider, run)
        assert facts == {
            "task_ids": {"/info/id": "19159"},
            "guest": CAPE_GUEST,
            "sandbox_version": "2.5",
            "sandbox_commit": CAPE_COMMIT,
            "started": "2026-08-13 13:06:05",
            "ended": "2026-08-13 13:09:06",
            "detonated": True,
            "report_parts": [{"name": "report", "sha256": _sha(body), "bytes": len(body)}],
        }

    def test_triage_states_its_overview_and_each_body_as_fetched(self) -> None:
        from tests.unit.providers.sandbox.test_triage_provider import _provider

        overview = (FIX / "triage_overview.json").read_bytes()
        task = (FIX / "triage_report_behavioral1.json").read_bytes()

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("overview.json"):
                return httpx.Response(200, content=overview)
            return httpx.Response(200, content=task)

        provider = _provider(handler)
        facts = stated_by(provider, provider.fetch("260904-abcdefgh1"))
        assert facts == {
            "task_ids": {"/sample/id": "260904-abcdefgh1"},
            # The task report's own platform; the overview row's ``target`` and
            # ``backend`` are no guest fact, and the sample's completion is not
            # this detonation's end.
            "guest": {"behavioral1": {"platform": "windows"}},
            "detonated": True,
            "report_parts": [
                {"name": "overview", "sha256": _sha(overview), "bytes": len(overview)},
                {"name": "behavioral1", "sha256": _sha(task), "bytes": len(task)},
            ],
        }

    def test_the_rest_provider_states_the_report_as_fetched(self) -> None:
        from tests.unit.providers.sandbox.test_rest_provider import _cfg, _provider

        # Written as a sandbox writes it, not as a parser would write it back.
        body = b'{\n  "procs" : [ ],\n  "target" : { "sha256" : "ab" }\n}\n'
        provider = _provider(lambda request: httpx.Response(200, content=body), _cfg())
        facts = stated_by(provider, provider.fetch("T-9"))
        assert facts == {
            "detonated": True,
            "report_parts": [{"name": "report", "sha256": _sha(body), "bytes": len(body)}],
        }

    def test_the_mock_states_the_fixture_it_read_and_that_nothing_was_detonated(
        self, tmp_path: Path
    ) -> None:
        from malspark.providers.sandbox.mock import MockSandboxProvider

        body = (FIX / "cape2_report.json").read_bytes()
        (tmp_path / "dynamic").mkdir()
        (tmp_path / "dynamic" / "s.json").write_bytes(body)
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        provider = MockSandboxProvider(str(tmp_path))
        facts = stated_by(provider, provider.fetch(provider.submit(str(sample))))
        assert facts is not None
        assert facts["detonated"] is False
        assert facts["report_parts"] == [
            {"name": "s.json", "sha256": _sha(body), "bytes": len(body)}
        ]
        assert facts["sandbox_version"] == "2.5"

    def test_the_mock_s_stand_in_was_read_from_nothing(self, tmp_path: Path) -> None:
        from malspark.providers.sandbox.mock import MockSandboxProvider

        sample = tmp_path / "none.exe"
        sample.write_bytes(b"payload")
        provider = MockSandboxProvider(str(tmp_path))
        facts = stated_by(provider, provider.fetch(provider.submit(str(sample))))
        assert facts == {"detonated": False, "report_parts": []}

    def test_the_upload_provider_states_the_bytes_it_read_and_that_nothing_was_detonated(
        self,
    ) -> None:
        from malspark.providers.sandbox.upload import UploadSandboxProvider

        blob = (FIX / "cape2_report.json").read_bytes()
        provider = UploadSandboxProvider.from_settings(Settings(_env_file=None))
        provider.set_pending_blob(blob, filename="r.json")
        facts = stated_by(provider, provider.fetch("uploaded"))
        assert facts is not None
        assert facts["detonated"] is False
        assert facts["report_parts"] == [
            {"name": "report", "sha256": _sha(blob), "bytes": len(blob)}
        ]
        assert facts["task_ids"] == {"/info/id": "19159"}

    def test_a_run_built_without_parts_states_none(self) -> None:
        from tests.unit.test_sandbox_container import _stub_run

        assert report_facts(_stub_run(), detonated=True)["report_parts"] == []


# ---------------------------------------------------------------------------
# What is read from where: the format declared for the job, the build, every part


# A format an operator declares (``sandbox.report_formats``): its task id sits
# where no shipped declaration looks.
ACME = {
    "name": "acme",
    "detect": [[{"path": "/producer/name", "contains": "acme"}]],
    "task_id_paths": ["/run/ticket"],
    "reader": "cape2",
}
ACME_PAYLOAD = {
    "producer": {"name": "ACME detonator 3"},
    "run": {"ticket": "T-77"},
    "info": {"id": 1, "version": "3.1"},
    "behavior": {"processes": []},
    "signatures": [],
}


class TestWhatIsReadFromWhere:
    def test_the_upload_reads_the_task_id_where_the_declared_format_says(self) -> None:
        from malspark.providers.sandbox.upload import UploadSandboxProvider

        settings = Settings.model_validate(
            {
                "sandbox": {
                    "provider": "upload",
                    "report_formats": [ACME],
                    "upload": {"allowed_formats": ["acme"]},
                }
            }
        )
        provider = UploadSandboxProvider.from_settings(settings)
        provider.set_pending_blob(json.dumps(ACME_PAYLOAD).encode(), filename="r.json")
        facts = stated_by(provider, provider.fetch("uploaded")) or {}
        assert facts["task_ids"] == {"/run/ticket": "T-77"}
        assert facts["sandbox_version"] == "3.1"

    def test_the_rest_provider_reads_the_task_id_through_the_mapped_reader_s_format(
        self,
    ) -> None:
        from tests.unit.providers.sandbox.test_rest_provider import _provider

        declared = {
            "name": "acme_box",
            "detect": [[{"path": "/acme", "types": ["object"]}]],
            "task_id_paths": ["/acme/ticket"],
            "reader": "generic",
            "mapping": {"target_sha256": "", "processes": "$.acme.procs[*]"},
        }
        cfg = Settings.model_validate(
            {
                "sandbox": {
                    "provider": "rest",
                    "report_formats": [declared],
                    "rest": {
                        "base_url": "https://xyz.example/api",
                        "report": {"format": "acme_box"},
                    },
                }
            }
        )
        body = json.dumps({"acme": {"ticket": "R-5", "procs": []}}).encode()
        provider = _provider(lambda request: httpx.Response(200, content=body), cfg)
        facts = stated_by(provider, provider.fetch("R-5")) or {}
        assert facts["task_ids"] == {"/acme/ticket": "R-5"}

    def test_a_shipped_format_is_read_where_no_format_is_declared(self) -> None:
        from malspark.providers.sandbox.readers import report_reader

        reader = report_reader("cape2")
        assert reader is not None
        assert reader.run_facts({"info": {"id": 9}})["task_ids"] == {"/info/id": "9"}

    def test_the_cape_report_s_build_is_its_version_and_its_commit(self) -> None:
        from malspark.providers.sandbox.readers import report_reader

        reader = report_reader("cape2")
        assert reader is not None
        facts = reader.run_facts({"info": {"version": "2.5", "CAPE_current_commit": "abc1"}})
        assert facts["sandbox_version"] == "2.5" and facts["sandbox_commit"] == "abc1"
        assert "sandbox_commit" not in reader.run_facts({"info": {"version": "2.5"}})
        (row,) = detonations_record(_held(_record())) or []
        assert row["sandbox_commit"] == CAPE_COMMIT

    def test_each_triage_task_states_its_own_guest_and_no_start_or_end(self) -> None:
        from tests.unit.providers.sandbox.test_triage_provider import _provider

        # The overview a live API answered: ``resource`` and ``os`` name the
        # machine, ``target`` the analysed file, ``backend`` the worker.
        overview = (FIX / "triage_overview_dict_tasks.json").read_bytes()
        task = json.loads((FIX / "triage_report_behavioral1.json").read_text(encoding="utf-8"))
        bodies = {
            "overview.json": overview,
            "behavioral1/report_triage.json": json.dumps(task).encode(),
        }

        def handler(request: httpx.Request) -> httpx.Response:
            for tail, body in bodies.items():
                if request.url.path.endswith(tail):
                    return httpx.Response(200, content=body)
            return httpx.Response(404)

        provider = _provider(handler)
        facts = stated_by(provider, provider.fetch("260907-slyq5axxbt")) or {}
        assert facts["guest"] == {
            # The overview row's image and system; the task report's platform.
            "behavioral1": {
                "resource": "win10v2004-20260513-en",
                "os": "windows10-2004-x64",
                "platform": "windows",
            },
            "behavioral2": {
                "resource": "win11ltsc2024-20260709-en",
                "os": "windows11-ltsc_2024-x64",
            },
        }
        text = json.dumps(facts["guest"])
        assert ".dll" not in text and "sbx4m" not in text
        # No part states one detonation's start or end.
        assert "started" not in facts and "ended" not in facts
        # With the worker's values registered, as in a run, the row keeps each
        # image and system name as the sandbox wrote it.
        from malspark.pipeline.events import remember_secret_values

        remember_secret_values([password(20, variant=7)])
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        assert row["guest"] == facts["guest"]
        assert row["started"] == NR and row["ended"] == NR
        assert row["sandbox_version"] == NR and row["sandbox_commit"] == NR

    def test_a_reader_that_cannot_say_leaves_the_report_read(self) -> None:
        from malspark.providers.sandbox.readers import run_facts_of

        class _Old:
            def run_facts(self, payload: Any) -> dict[str, Any]:
                return {"guest": {"name": "x"}}

        assert run_facts_of(_Old(), {}, None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# What a row keeps of what it is given


class TestWhatARowKeeps:
    def test_a_start_or_an_end_stated_alone_leaves_the_other_not_reported(self) -> None:
        facts = _facts()
        del facts["started"]
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        assert row["started"] == NR and row["ended"] == "2026-08-13 13:09:06"
        facts = _facts()
        del facts["ended"]
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        assert row["ended"] == NR and row["started"] == "2026-08-13 13:06:05"

    def test_hostile_text_in_every_text_fact_is_kept_inert(self) -> None:
        hostile = HOSTILE
        facts = _facts(
            task_ids={hostile: hostile},
            guest={hostile: hostile, "task": {hostile: hostile}},
            sandbox_version=hostile,
            sandbox_commit=hostile,
            started=hostile,
            ended=hostile,
            report_parts=[{"name": hostile, "sha256": "0" * 64, "bytes": 1}],
        )
        record = _record(sandbox_facts=facts, provider=hostile, task_id=hostile, failure=hostile)
        (row,) = detonations_record(_held(record)) or []

        def texts(value: Any) -> list[str]:
            if isinstance(value, dict):
                return [t for k, v in value.items() for t in [k, *texts(v)]]
            if isinstance(value, list):
                return [t for v in value for t in texts(v)]
            return [value] if isinstance(value, str) else []

        kept = texts({k: v for k, v in row.items() if k != "launched_with"})
        assert kept
        for text in kept:
            assert len(text) <= STATED_TEXT_CHARS, text
            assert not any(unicodedata.category(ch).startswith("C") for ch in text), text
        assert "`|<x>{y}" in row["sandbox_commit"] and row["ended"]

    def test_a_mapping_keeps_at_most_its_entry_cap(self) -> None:
        many = {f"id{n:02}": str(n) for n in range(STATED_ENTRIES + 8)}
        guest = {f"task{n:02}": {"os": "x"} for n in range(STATED_ENTRIES + 8)}
        facts = _facts(task_ids=many, guest=guest)
        (row,) = detonations_record(_held(_record(sandbox_facts=facts))) or []
        assert list(row["task_ids"]) == list(many)[:STATED_ENTRIES]
        assert list(row["guest"]) == list(guest)[:STATED_ENTRIES]

    def test_an_agent_that_asked_twice_is_named_once(self) -> None:
        record = _record(
            ordinal=2,
            origin=AGENT_ORIGIN,
            requested_by=[{"agent": "static"}, {"agent": "network"}, {"agent": "static"}],
        )
        (row,) = detonations_record(_held(record)) or []
        assert row["requested_by"] == ["static", "network"]

    def test_a_guest_per_task_is_kept_per_task(self) -> None:
        guest = {"behavioral1": {"resource": "win10", "os": "windows10"}, "flat": "x"}
        (row,) = detonations_record(_held(_record(sandbox_facts=_facts(guest=guest)))) or []
        assert row["guest"] == guest

    def test_a_launch_that_states_no_honouring_is_not_reported(self) -> None:
        for launch in ({}, {"honoured": "yes"}, None):
            record = _record(arguments="-k netsvcs", launch=launch)
            (row,) = detonations_record(_held(record)) or []
            assert row["launched_with"] == "-k netsvcs"
            assert row["arguments_honoured"] == NR, launch


# ---------------------------------------------------------------------------
# Through the real path: the job's detonation, made by the app


def _detonated(provider: Any, sample: Path) -> Any:
    import asyncio

    from malspark.app import MalsparkApp

    app = MalsparkApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    asyncio.run(app._submit_to_sandbox(str(sample)))
    return app.container


class TestThroughTheRun:
    def test_the_mock_sandbox_s_detonation_is_recorded_with_its_fixture(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.providers.sandbox.mock import MockSandboxProvider

        monkeypatch.setattr(run_environment, "host_facts", lambda: {})
        body = (FIX / "cape2_report.json").read_bytes()
        (tmp_path / "dynamic").mkdir()
        (tmp_path / "dynamic" / "s.json").write_bytes(body)
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")

        container = _detonated(MockSandboxProvider(str(tmp_path)), sample)
        record = environment_record(container)
        assert record is not None
        assert record["detonations"] == [
            {
                "detonation": "d1",
                "origin": "job",
                "provider": "mock",
                "task_id": "1",
                "reported": True,
                "detonated": False,
                "task_ids": {"/info/id": "19159"},
                "guest": CAPE_GUEST,
                "sandbox_version": "2.5",
                "sandbox_commit": CAPE_COMMIT,
                "started": "2026-08-13 13:06:05",
                "ended": "2026-08-13 13:09:06",
                "report_parts": [{"name": "s.json", "sha256": _sha(body), "bytes": len(body)}],
            }
        ]
        summary = RunSummaryBuilder(start_time=0.0).set_environment(record).build().to_dict()
        assert summary["environment"]["detonations"] == record["detonations"]

    def test_a_plug_in_through_the_run_is_recorded_as_not_reported(self, tmp_path: Path) -> None:
        from tests.unit.test_sandbox_container import _StubProvider

        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        container = _detonated(_StubProvider(), sample)
        (row,) = detonations_record(container) or []
        assert row["provider"] == "stub" and row["task_id"] == "42"
        assert row["reported"] is True
        assert row["detonated"] == NR and row["report_parts"] == NR

    def test_an_attached_report_is_recorded_as_read_and_not_detonated(self, tmp_path: Path) -> None:
        from malspark.providers.sandbox.upload import UploadSandboxProvider

        blob = (FIX / "cape2_report.json").read_bytes()
        provider = UploadSandboxProvider.from_settings(Settings(_env_file=None))
        provider.set_pending_blob(blob, filename="r.json")
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        (row,) = detonations_record(_detonated(provider, sample)) or []
        assert row["provider"] == "upload" and row["reported"] is True
        assert row["detonated"] is False
        assert row["task_ids"] == {"/info/id": "19159"}
        assert row["sandbox_commit"] == CAPE_COMMIT
        assert row["report_parts"] == [{"name": "report", "sha256": _sha(blob), "bytes": len(blob)}]

    def test_a_run_in_mock_mode_records_no_detonation(self, tmp_path: Path) -> None:
        import asyncio

        from malspark.app import MalsparkApp

        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        app = MalsparkApp(mock=True)
        asyncio.run(app._submit_to_sandbox(str(sample)))
        assert detonations_record(app.container) == []
