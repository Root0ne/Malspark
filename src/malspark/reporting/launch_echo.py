"""A further detonation's launch text holds no value: it is the run's input, not an observation.

An agent may ask for a further detonation with launch arguments
(``providers.detonation``: ``d2``, ``d3``…). What that launch text supplies —
a folder, a host, a value the agent typed — is the run's own input to the
detonation, not something the sample did: the same principle as a call's own
echo (``pipeline.validation.held_only_in_its_echo``). A read of a further
detonation states its launch text (its ``launched_with`` field, and the end
of the launched process's command line). On the publish route
(``stated_host_values.scan_cited``) and the second-source route
(``stix_renderer.second_source_reads``) that text is a second echo the shared
pair-of-texts predicate reads a read without (``EntryTexts.with_launch_echoes``,
:func:`launch_echoed`); the citation checks read the read as before.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from functools import partial
from typing import Any, cast


def launch_echoed(entry: Any, values: Iterable[str], held: Any, corpus: Any = None) -> list[str]:
    """Each of ``values`` a read of a further detonation holds whole only where it states its
    launch text, by the second-source route's own test ``held`` (asked of a value and a text).

    The read's texts (its answer, the corpus's copy where kept, and its
    structured answer) each as a pair written the same way, whole and without
    the launch echo (``validation._without_call_echoes`` with the launch);
    the shared predicate (``validation.held_only_in_its_echo``) decides,
    its decoded-run exception included. ``[]`` for an entry that reads no
    further detonation.
    """
    from malspark.analysis.detonation_reads import later_detonation_name
    from malspark.pipeline.validation import (
        ECHO_FREE_HOLDS_IT,
        _without_call_echoes,
        held_only_in_its_echo,
    )
    from malspark.reporting.stated_host_values import encodings

    data = getattr(entry, "structured", None)
    launch = str(data.get("launched_with") or "") if isinstance(data, Mapping) else ""
    if not later_detonation_name(entry) or not launch.strip():
        return []
    written: list[str] = []
    if corpus is not None:
        try:
            from malspark.agents.run_evidence_corpus import read_of_entry

            written.append(read_of_entry(corpus, str(entry.id)) or "")
        except Exception:  # noqa: BLE001 — the stored answer is read instead
            written = []
    if not any(written):
        written = [str(getattr(entry, "output", "") or "")]
    if data:
        written.append(json.dumps(data, default=str))
    pairs: list[tuple[str, str | None]] = []
    for part in written:
        try:
            pairs.append(
                (_without_call_echoes(part, None), _without_call_echoes(part, None, launch=launch))
            )
        except RecursionError:
            pairs.append((part, None))
    texts = _PairsOf(tuple(pairs))
    out: list[str] = []
    for value in values:
        found = held_only_in_its_echo(
            cast(Any, texts),
            str(entry.id),
            partial(held, value),
            encodings(value),
        )
        if found and found != ECHO_FREE_HOLDS_IT:
            out.append(value)
    return out


class _PairsOf:
    """One entry's texts as the shared predicate reads them, already paired."""

    def __init__(self, pairs: tuple[tuple[str, str | None], ...]) -> None:
        self._pairs = pairs

    def echo_free_parts(
        self, entry_id: str, *, launch: bool = True
    ) -> tuple[tuple[str, str | None], ...]:
        del entry_id, launch
        return self._pairs
