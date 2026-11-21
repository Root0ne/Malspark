"""The judge's unconfirmed status is the last note of its row, and never beside its keeping.

``isr_models.is_judge_unconfirmed`` reads the status as a capability-matrix
row's last note, whole. That is exact only while the matrix appends
:data:`JUDGE_UNCONFIRMED_TECHNIQUE_MARKER` after every other note and never on
a row that carries :func:`judge_kept_note`, the one note that holds the judge's
own words. These tests pin both by construction: the real matrix builder over
the combinations of note conditions, and the builder's code itself.
"""

from __future__ import annotations

import ast
import inspect
import itertools
from pathlib import Path
from typing import Literal

import pytest

from malspark.extractors import capability_matrix
from malspark.extractors.capability_matrix import build_capability_matrix
from malspark.reporting.models import CapabilityCell
from malspark.schemas.isr_models import (
    CAPABILITY_NOTE_JOINER,
    JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
    AgentISR,
    ClaimEvidence,
    is_judge_unconfirmed,
    judge_kept_note,
)
from malspark.schemas.stix_models import (
    TECHNIQUE_REVIEW_PROPERTY,
    TechniqueDecision,
    TechniqueReview,
)

ASKED = "T1059"
UNDESCRIBED = "the ATT&CK check found that no claim naming it uses the catalogue's terms for it"
# A reason in the judge's own words that holds the joiner and the marker's words.
KEPT_REASON = f"the call is shown; {JUDGE_UNCONFIRMED_TECHNIQUE_MARKER}; the strings agree"

FIELD_INSTEAD = (
    "a note now stands after the judge's unconfirmed marker, or beside the judge's kept "
    "note: the status can no longer be read as the row's last note. Carry the status as a "
    "field of CapabilityCell instead, and read that field where the status is read"
)


def _cell(
    decision: Literal["keep", "drop"] | None,
    *,
    absence: bool,
    failed: bool,
    carried: bool,
    undescribed: bool,
) -> CapabilityCell:
    claim = ClaimEvidence(
        claim="The sample runs a command through the command interpreter",
        evidence_ref="[ev_0002]",
        confidence=0.6,
        technique_id=ASKED,
        kept_after_absence_question=absence,
        cites_only_failed_calls=failed,
        carried_since_round=1 if carried else None,
    )
    decisions = (
        [TechniqueDecision(technique_id=ASKED, decision=decision, reason=KEPT_REASON)]
        if decision
        else []
    )
    review = TechniqueReview(
        asked=[ASKED],
        decisions=decisions,
        undescribed={ASKED: UNDESCRIBED} if undescribed else {},
    )
    bundle = {
        "type": "bundle",
        "objects": [],
        TECHNIQUE_REVIEW_PROPERTY: review.model_dump(mode="json"),
    }
    cells, _mappings = build_capability_matrix(
        stix_output=bundle,
        isr_reports={
            "static": AgentISR(agent_id="static", domain="static", revision_round=0, claims=[claim])
        },
    )
    return next(c for c in cells if c.technique_id == ASKED)


@pytest.mark.parametrize(
    ("decision", "absence", "failed", "carried", "undescribed"),
    list(itertools.product([None, "keep", "drop"], *[[False, True]] * 4)),
)
def test_the_matrix_puts_the_marker_last_and_never_beside_the_judge_s_keeping(
    decision: Literal["keep", "drop"] | None,
    absence: bool,
    failed: bool,
    carried: bool,
    undescribed: bool,
) -> None:
    cell = _cell(decision, absence=absence, failed=failed, carried=carried, undescribed=undescribed)
    notes = cell.note.split(CAPABILITY_NOTE_JOINER) if cell.note else []

    if decision is None:
        # Not answered: the marker is the last note, after every other.
        assert notes[-1] == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER, FIELD_INSTEAD
        assert notes.count(JUDGE_UNCONFIRMED_TECHNIQUE_MARKER) == 1, FIELD_INSTEAD
        assert is_judge_unconfirmed(cell.note)
    elif decision == "keep":
        # Kept: the judge's note, with its reason, is the last note and no marker is added.
        assert cell.note.endswith(judge_kept_note(KEPT_REASON)), FIELD_INSTEAD
        before = cell.note[: -len(judge_kept_note(KEPT_REASON))]
        assert JUDGE_UNCONFIRMED_TECHNIQUE_MARKER not in before, FIELD_INSTEAD
        assert not is_judge_unconfirmed(cell.note)
    else:
        # Dropped: not published, and neither note is on the row.
        assert cell.not_published
        assert JUDGE_UNCONFIRMED_TECHNIQUE_MARKER not in cell.note, FIELD_INSTEAD
        assert judge_kept_note("") not in cell.note
        assert not is_judge_unconfirmed(cell.note)


def _notes_writes(func: ast.AST) -> list[ast.stmt | ast.expr]:
    """Every statement or call in ``func`` that writes the local ``notes`` list."""
    out: list[ast.stmt | ast.expr] = []
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "notes"
            and node.func.attr in {"append", "extend", "insert", "pop", "remove", "clear"}
        ):
            out.append(node)
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = list(node.targets) if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                base = target.value if isinstance(target, ast.Subscript) else target
                if isinstance(base, ast.Name) and base.id == "notes":
                    out.append(node)
    return out


def _appends(node: ast.AST, name: str) -> bool:
    """Whether ``node`` is ``notes.append(<name>)`` or ``notes.append(<name>(...))``."""
    if not (isinstance(node, ast.Call) and node.args):
        return False
    arg = node.args[0]
    called = arg.func if isinstance(arg, ast.Call) else arg
    return isinstance(called, ast.Name) and called.id == name


def test_the_builder_s_code_appends_nothing_after_the_marker() -> None:
    source = inspect.getsource(build_capability_matrix)
    func = ast.parse(source).body[0]
    writes = _notes_writes(func)
    marker = [w for w in writes if _appends(w, "JUDGE_UNCONFIRMED_TECHNIQUE_MARKER")]
    kept = [w for w in writes if _appends(w, "judge_kept_note")]
    assert len(marker) == 1 and len(kept) == 1, FIELD_INSTEAD

    # The two are the branches of one ``if``/``elif``: never both on one row.
    branch = next(
        node
        for node in ast.walk(func)
        if isinstance(node, ast.If)
        and any(n is kept[0] for stmt in node.body for n in ast.walk(stmt))
    )
    assert len(branch.orelse) == 1 and isinstance(branch.orelse[0], ast.If), FIELD_INSTEAD
    assert any(n is marker[0] for n in ast.walk(branch.orelse[0])), FIELD_INSTEAD

    # No write of the notes comes after that ``if`` in the code.
    end = branch.end_lineno or branch.lineno
    after = [w for w in writes if w.lineno > end]
    assert after == [], FIELD_INSTEAD

    # The row's one note is the notes joined, and this builder is its only writer.
    cell_calls = [
        node
        for node in ast.walk(func)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "CapabilityCell"
    ]
    assert len(cell_calls) == 1
    [note] = [kw.value for kw in cell_calls[0].keywords if kw.arg == "note"]
    assert ast.unparse(note) == "CAPABILITY_NOTE_JOINER.join(notes)", FIELD_INSTEAD


def test_no_other_code_writes_a_capability_cell_s_note() -> None:
    src = Path(capability_matrix.__file__).resolve().parents[1]
    writers: list[str] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "CapabilityCell"
                and any(kw.arg == "note" for kw in node.keywords)
            ):
                writers.append(path.relative_to(src).as_posix())
    assert writers == ["extractors/capability_matrix.py"], FIELD_INSTEAD
