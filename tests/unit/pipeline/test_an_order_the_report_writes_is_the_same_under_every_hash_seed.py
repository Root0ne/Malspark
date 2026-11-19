"""An order the platform writes is a function of the data, never of the hash seed.

A list taken from a set of strings in iteration order differs between two
processes, because each salts string hashes its own way. The entries one
statement cites are listed sorted, the roots of several statements in the order
the statements come, and every other order the record or the console writes
from a set is sorted by the member itself. ``written_orders.py`` prints them;
it runs here under four seeds, one process each.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

HELPER = Path(__file__).with_name("written_orders.py")

EXPECTED: dict[str, Any] = {
    "corroboration": {
        # The first statement's entries sorted, then the later statement's.
        "evidence_roots": [
            "0x180001100",
            "0x180001300",
            "0x180001500",
            "0x180001700",
            "0x180001900",
            "0x180001c00",
            "0x180001200",
            "0x180001b00",
        ],
        "roots_not_read": [
            "ev_0100: no: ev_0100 is not an entry of this run's ledger",
            "ev_0101: no: ev_0101 is not an entry of this run's ledger",
            "ev_0102: no: ev_0102 is not an entry of this run's ledger",
        ],
        "sources": [
            "ev_0001",
            "ev_0003",
            "ev_0005",
            "ev_0007",
            "ev_0009",
            "ev_0012",
            "ev_0002",
            "ev_0011",
        ],
    },
    "dropped_values": ["0x401000", "T1027", "Alpha", "bravo", "charlie", "delta", "echo"],
    "platform_warnings": [
        f"executive_summary mentions '{term}' but sample platform is linux."
        for term in ("azure", "cloud auth", "macos", "powershell")
    ],
    "missing_models": "1 models available; missing ['qwen-a', 'qwen-b']",
    "server_status": "mcp server 'network' answered without a listing",
}


SEEDS = ("0", "1", "2", "3")


def _written() -> dict[str, dict[str, Any]]:
    """The helper's output per seed, the four processes run at once."""
    running = {
        seed: subprocess.Popen(  # noqa: S603 - this interpreter and a script of this repository
            [sys.executable, str(HELPER)],
            env={**os.environ, "PYTHONHASHSEED": seed},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for seed in SEEDS
    }
    written: dict[str, dict[str, Any]] = {}
    for seed, process in running.items():
        out, err = process.communicate(timeout=120)
        assert process.returncode == 0, f"seed {seed}: {err[-2000:]}"
        written[seed] = json.loads(out)
    return written


def test_every_seed_writes_the_order_the_data_gives() -> None:
    written = _written()
    for seed, orders in written.items():
        assert orders == written["0"], f"seed {seed} differs from seed 0"
    for seed, orders in written.items():
        assert orders == EXPECTED, f"seed {seed}"
