"""A later detonation's network rows pass through the attribution and noise rules the first's do.

The platform's read of a further detonation launched through a generated
launcher states which flows the sample's tree made and which the launcher's
script host made (``sandbox_report.attribute_the_launcher``). Its rows in the
network block keep that attribution, the public-resolver fact is read for
them as for any address, and the one publish rule answers them by it: the
launcher's own flow is never published as the sample's (T-671 review r2, an
unverified point). Offline.
"""

from __future__ import annotations

from typing import Any

from malspark.pipeline.detonations import platform_reads
from malspark.providers.detonation import DetonationRecord
from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.ledger_projection import network_from_ledger
from malspark.reporting.models import FileHashes, MalwareReport, SampleIdentity
from malspark.schemas.evidence import LedgerEntry
from malspark.schemas.sandbox_document import sandbox_document
from tests.unit.pipeline.test_a_launcher_run_is_read_as_the_launcher_s import _attributed, _task


class _Container:
    event_sink = None
    detonations: list[Any] = []


def _network() -> Any:
    task = _task()
    # A lookup the sample's child made to a public resolver.
    task["network"]["flows"].append({"proto": "udp", "dst": "8.8.8.8:53", "procid": 3})
    record = DetonationRecord(
        ordinal=2, origin="agent", arguments="-x", report=sandbox_document(_attributed(task=task))
    )
    ledger = [LedgerEntry.model_validate(row) for row in platform_reads(_Container(), record, "")]
    return network_from_ledger(ledger)


def test_the_sample_s_and_the_launcher_s_flows_keep_their_attribution() -> None:
    network = _network()
    ips = {ip.address: ip for ip in network.ips}
    assert ips["203.0.113.5"].sample_process_tree is True
    launcher = ips["198.51.100.7"]
    assert launcher.sample_process_tree is False
    assert launcher.outside_processes == ["powershell.exe (procid 1)"]
    assert all([m.detonation for m in ip.observed_in] == ["d2"] for ip in network.ips)


def test_the_public_resolver_fact_is_read_for_a_later_detonation_s_address() -> None:
    ips = {ip.address: ip for ip in _network().ips}
    assert ips["8.8.8.8"].public_resolver is True
    assert ips["203.0.113.5"].public_resolver is False


def test_the_publish_rule_never_publishes_the_launcher_s_flow() -> None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="6" * 64)),
        verdict="Malware",
        network=_network(),
    )
    rows = {row.value: row for row in build_consolidated_iocs(report)}
    assert str(rows["198.51.100.7"].published).startswith("no")
    assert str(rows["8.8.8.8"].published).startswith("no")
