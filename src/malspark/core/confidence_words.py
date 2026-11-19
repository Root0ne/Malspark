"""The words a confidence number reads as: one table for every surface that words one.

The report prints a confidence beside its band (``reporting.renderers.markdown``),
and the judge is shown the same bands where it is asked for its confidence
(``agents.judge_agent``), so the word a rationale gives a number is the word
the report prints for it. Kept below both, so neither imports the other.
"""

from __future__ import annotations

# The word a number reads as. A deterministic reading of the producer's own
# number, printed beside it and never instead of it. Only confidence levels are
# written here; likelihood words belong to the models' prose.
CONFIDENCE_WORDS: tuple[tuple[float, str], ...] = (
    (0.90, "high confidence"),
    (0.70, "moderate-to-high confidence"),
    (0.50, "moderate confidence"),
    (0.30, "low confidence"),
    (0.0, "very low confidence"),
)


def confidence_word(value: float | None) -> str:
    """The fixed word for a confidence number, or ``not assessed`` for none."""
    if value is None:
        return "not assessed"
    rounded = round(float(value), 2)
    for floor, word in CONFIDENCE_WORDS:
        if rounded >= floor:
            return word
    return CONFIDENCE_WORDS[-1][1]


def confidence_bands() -> str:
    """The table as one line of prose.

    ``high confidence from 0.90, …, very low confidence below 0.30``.
    """
    bands = [f"{word} from {floor:.2f}" for floor, word in CONFIDENCE_WORDS[:-1]]
    floor = CONFIDENCE_WORDS[-2][0]
    bands.append(f"{CONFIDENCE_WORDS[-1][1]} below {floor:.2f}")
    return ", ".join(bands)
