"""Build a stored run's limitations inventory, at zero cost.

Over one or more stored runs, each a directory in the benchmark's layout::

    python scripts/replay/limitation_inventory.py <run dir> [<run dir> ...]

builds the inventory the report node now builds before the report's prose is
written (``reporting.limitation_inventory.build_inventory``) from what the run
stored: the ledger (``evidence.json``) and the report (``report.json``), its
recorded limitations and open questions as they stood. It prints, per run, the
list section 11 of the analyst report prints, then every row the writer and the
agreement round are shown that it does not print. A stored report holds no
inventory and renders as it did; this is what a run that holds one prints.

Read-only over the runs: nothing is written beside them, no network is reached,
no credential is read. ``--json PATH`` writes each run's record and rows to
``PATH``; ``--golden DIR`` writes each run's record to ``DIR/<run>.json``, the
golden a test compares the build with.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def stored_inventory(run: Path) -> tuple[Any, Any]:
    """The stored report of ``run`` and the inventory built from its ledger."""
    from scripts.replay.stored import evidence_rows

    from malspark.reporting.follow_up import stored_ledger
    from malspark.reporting.limitation_inventory import build_inventory
    from malspark.reporting.models import MalwareReport

    rows, _why = evidence_rows(json.loads((run / "evidence.json").read_bytes()))
    ledger: list[Any] = stored_ledger(rows)[0]
    report = MalwareReport.model_validate(json.loads((run / "report.json").read_bytes()))
    return report, build_inventory(report, ledger)


def read_run(run: Path) -> dict[str, Any]:
    """One stored run's inventory, its printed list and its other rows."""
    from malspark.reporting.limitation_inventory import inventory_rows, reason_label

    report, inventory = stored_inventory(run)
    rows = inventory_rows(
        inventory, reason_as=reason_label, claims_not_discussed=len(report.claims_not_discussed)
    )
    return {
        "run": run.name,
        "inventory": inventory.model_dump(mode="json"),
        "printed": [row.text for row in rows if row.printed],
        "not_printed": [row.text for row in rows if not row.printed],
    }


def _print(read: dict[str, Any]) -> None:
    from scripts.replay.output import terminal_safe

    from malspark.reporting.limitation_inventory import LIST_LABEL

    # The run's name and the rows' words come from the stored run: shown, never obeyed.
    print(f"== {terminal_safe(read['run'])}")
    print(LIST_LABEL)
    for text in read["printed"]:
        print(f"- {terminal_safe(text)}")
    print("Shown, not printed:")
    for text in read["not_printed"]:
        print(f"  * {terminal_safe(text)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("runs", nargs="+", type=Path, help="stored run directories")
    parser.add_argument("--json", type=Path, default=None, help="write the records here too")
    parser.add_argument("--golden", type=Path, default=None, help="write one golden per run here")
    args = parser.parse_args(argv)
    found = []
    for run in args.runs:
        read = read_run(run)
        _print(read)
        found.append(read)
        if args.golden is not None:
            args.golden.mkdir(parents=True, exist_ok=True)
            (args.golden / f"{run.name}.json").write_text(
                json.dumps(read, indent=2, ensure_ascii=False) + "\n"
            )
    if args.json is not None:
        args.json.write_text(json.dumps(found, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
