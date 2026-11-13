"""What a check's finding leads to in this run: a correction turn, or a record alone.

``validation.feedback`` is ``feed_back`` (the default) or ``record_only``. In
``record_only`` every validator still runs and every finding is recorded as
it is in ``feed_back``, marked not asked; no correction turn and no follow-on
question is sent, and the answer stands as written. The rule is one for every
stage. A finding that says the answer, or a part of it, could not be read or
is absent where the stage substitutes a fallback of its own, so that left
unasked the agent's own content would be lost to it, is asked in both modes
(``validation.REASKED_IN_EVERY_MODE_CODES``, whose comment states the
criterion). What code does after a stage with what is
left standing, and every integrity guard, is the same in both.

The mode is read from the run's settings where a stage asks, as every other
``validation.*`` value is, so a replay that installs a stored run's snapshot
reads that run's mode.
"""

from __future__ import annotations

from typing import Any

SETTING = "validation.feedback"
FEED_BACK = "feed_back"
RECORD_ONLY = "record_only"
MODES = (FEED_BACK, RECORD_ONLY)

# Why a technique the judge's technique question would have asked about was
# not asked in ``record_only`` (``TechniqueReview.not_asked``).
NOT_ASKED_IN_RECORD_ONLY = f"not asked: {SETTING} is {RECORD_ONLY}"

# The operator's choice a ``record_only`` run lists beside its degradations
# (``run_summary.operator_choices``): it cost the run no evidence.
RECORD_ONLY_CHOICE = (
    f"{SETTING} is {RECORD_ONLY}: every check ran and every finding was recorded, "
    "and no agent was asked to correct its answer"
)


def feedback_mode(settings: Any = None) -> str:
    """This run's ``validation.feedback``, the default where it is not readable.

    ``settings`` is read when given; otherwise the process's settings. A value
    this module does not know is the default, never a third behaviour.
    """
    if settings is None:
        try:
            from malspark.core.config import get_settings

            settings = get_settings()
        except Exception:  # noqa: BLE001 — no settings, the default
            return FEED_BACK
    mode = getattr(getattr(settings, "validation", None), "feedback", FEED_BACK)
    return mode if mode in MODES else FEED_BACK


def feeds_back(settings: Any = None) -> bool:
    """Whether a finding opens a correction turn in this run."""
    return feedback_mode(settings) == FEED_BACK
