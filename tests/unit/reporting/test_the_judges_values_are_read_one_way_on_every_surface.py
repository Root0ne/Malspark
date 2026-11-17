"""A generated net over the judge's indicators: every pattern shape, place and verdict.

Each case builds a report the way the builder records the judge's values
(``stix_renderer.exported_indicator_values``) and renders the table, ``/iocs``
and the STIX export over it. The cases cross:

* the shape of the judge's indicators: one comparison; the value beside the
  sample's own digest, joined by ``AND`` and by ``OR``; the value beside a
  comparison that names no value; the value beside a value of another kind;
  the value written in another case; an indicator the export declines beside
  one it carries, in both orders;
* where else the value stands: nowhere, the string sweep without and with a
  second source, a sandbox host row, the network block; each with a value whose
  shape passes and one whose shape fails the shape question where it applies;
* each verdict, with and without a confidence.

It asserts the properties the rules state, not a list of answers:

(a) every value of a judge indicator the export carries has a row;
(b) a judge indicator is declined only for a reason true of it: its pattern's
    problem, or a value of it whose row is not published, which the reason names;
(c) a row of the string sweep answers as it would with no judge indicator,
    except where the answer without it is the shape question's refusal;
(d) a published row's type is the type of an object the bundle carries for its
    value, and no row reads a type from an indicator the export declines;
(e) the feed's published set equals the bundle's indicator values, with one
    stated exception: a row published on the judge's naming whose judge
    indicators the export carries none of has no object — a string-sweep path
    whose shape the naming lifted (declined by its pattern, or by the lookup),
    or a value only a one-value judge indicator the export declines names (as
    before this rule, a follow-up of its own);
(f) naming through an indicator the export declines keeps a sandbox row and
    lifts the shape question exactly as naming through one it carries does,
    and changes nothing else of the row;
(g) a value nobody else holds has a row exactly where the judge's naming gives
    one: a carried indicator naming it, or an indicator naming it and no other
    value, carried or not; and no object of the platform's is minted for a
    judge's row.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

import pytest

from app.services.report_service import ioc_feed_rows
from malspark.reporting.builder import ioc_table
from malspark.reporting.models import (
    DynamicBehavior,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from malspark.reporting.renderers.stix_renderer import (
    CLASS_REFERENCE_PATH,
    COMPILE_ARTIFACT_PATH,
    NOT_A_FILE_SHAPE,
    ExtendedSTIXRenderer,
    exported_indicator_values,
    pattern_problem,
    pattern_values,
    publishes,
    rule_values,
)
from malspark.schemas.stix_models import Bundle

SHA256 = "a" * 64
MD5 = "c" * 32
SHAPE_REFUSALS = (NOT_A_FILE_SHAPE, COMPILE_ARTIFACT_PATH, CLASS_REFERENCE_PATH)

# The values: a path whose shape passes, one whose shape fails, a network name.
VALUES = {
    "path-shaped": ("path", "C:\\ProgramData\\relay.dat"),
    "path-unshaped": ("path", "/opt/relay/bin/agentd"),
    "domain": ("domain", "relay-c2.example.net"),
}
# Where else each value stands.
PLACES = {
    "path": ("nowhere", "second-source", "sweep", "sweep-second-source", "host-row"),
    "domain": ("nowhere", "sweep", "network"),
}
VERDICTS = [(v, c) for v in ("Malware", "Suspicious", "Benign") for c in (0.9, None)]


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\")


def _comparison(kind: str, value: str) -> str:
    return f"file:name = '{_esc(value)}'" if kind == "path" else f"domain-name:value = '{value}'"


def _indicator(index: int, pattern: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433322{index:02d}",
        "name": f"judge {index}",
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
        "valid_from": "2026-01-01T00:00:00Z",
    }


def _shapes(kind: str, value: str) -> dict[str, list[str]]:
    """The judge's indicators for one value, by shape."""
    one = _comparison(kind, value)
    digest = f"file:hashes.MD5 = '{MD5}'"
    same_object = kind == "path"
    # A pattern the export declines whole: one comparison the grammar refuses (a
    # stray backslash in a quoted value) where the value holds a backslash, else
    # a property its object type does not have.
    object_type = "file" if kind == "path" else "domain-name"
    declined = (
        f"[file:name = '{value}']"
        if "\\" in value
        else f"[{one} AND {object_type}:no_such_property = 'x']"
    )
    return {
        "one": [f"[{one}]"],
        "and-digest": [f"[{one} AND {digest}]" if same_object else f"[{one}] AND [{digest}]"],
        "or-digest": [f"[{one} OR {digest}]" if same_object else f"[{one}] OR [{digest}]"],
        "beside-no-value": [f"[{one} AND file:size > 10]" if same_object else f"[{one}]"],
        "two-kinds": [f"[{one}] OR [domain-name:value = 'other-c2.example.org']"],
        # Beside the sample's own digest, its key quoted, so both are values read.
        "and-own-digest": [
            f"[{one} AND file:hashes.'MD5' = '{MD5}']"
            if same_object
            else f"[{one}] AND [file:hashes.'MD5' = '{MD5}']"
        ],
        "two-kinds-joined": [f"[{one}] AND [domain-name:value = 'other-c2.example.org']"],
        "cased": [f"[{_comparison(kind, value.upper())}]"],
        "declined-first": [declined, f"[{one}]"],
        "declined-second": [f"[{one}]", declined],
        "declined-only": [declined],
    }


def _report(
    kind: str, value: str, place: str, verdict: str, confidence: float | None, judge: dict
) -> MalwareReport:
    fields: dict[str, Any] = {}
    if place.startswith("sweep"):
        fields["static"] = StaticAnalysis(interesting_strings=[StringIOC(kind=kind, value=value)])
    if place in ("second-source", "sweep-second-source"):
        fields["dynamic"] = DynamicBehavior(
            process_tree=[{"pid": 1, "name": "s.exe", "command_line": f"s.exe {value}"}]
        )
    if place == "host-row":
        fields["dynamic"] = DynamicBehavior(
            process_tree=[{"pid": 1, "name": f"{SHA256}.exe"}],
            file_operations=[{"operation": "write", "path": value, "pid": 1}],
        )
    if place == "network":
        fields["network"] = NetworkIOCs(domains=[NetworkDomain(fqdn=value, source="sandbox")])
    recorded = [
        JudgeIndicator(
            **{
                key: (list(item) if isinstance(item, tuple) else item)
                for key, item in dataclasses.asdict(found).items()
                if key in JudgeIndicator.model_fields
            }
        )
        for found in exported_indicator_values(judge)
    ]
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256, sha1="b" * 40, md5=MD5)),
        verdict=verdict,  # type: ignore[arg-type]
        overall_confidence=confidence,
        malware_category="loader",
        judge_indicators=recorded,
        **fields,
    )


def _key(kind: str, value: str) -> tuple[str, str]:
    return kind, value.strip().lower()


def _bundle_values(bundle: dict[str, Any]) -> dict[tuple[str, str], list[list[str]]]:
    out: dict[tuple[str, str], list[list[str]]] = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "indicator":
            continue
        for found in pattern_values(str(obj.get("pattern") or "")):
            out.setdefault(_key(found.kind, found.value), []).append(obj["indicator_types"])
    return out


CASES = [
    pytest.param(
        label,
        kind,
        value,
        place,
        shape,
        verdict,
        confidence,
        id=f"{label}-{place}-{shape}-{verdict}-{confidence}",
    )  # fmt: skip
    for label, (kind, value) in VALUES.items()
    for place in PLACES[kind]
    for shape in _shapes(kind, value)
    for verdict, confidence in VERDICTS
]


@pytest.mark.parametrize(
    ("label", "kind", "value", "place", "shape", "verdict", "confidence"), CASES
)
def test_the_judges_values_hold_every_property(
    label: str,
    kind: str,
    value: str,
    place: str,
    shape: str,
    verdict: str,
    confidence: float | None,
) -> None:
    patterns = _shapes(kind, value)[shape]
    judge = {"type": "bundle", "objects": [_indicator(i, p) for i, p in enumerate(patterns)]}
    report = _report(kind, value, place, verdict, confidence, judge)
    rows = ioc_table(report)
    report = report.model_copy(update={"consolidated_iocs": rows})
    renderer = ExtendedSTIXRenderer()
    bundle = renderer.render(report, Bundle.model_validate(judge)).model_dump(mode="json")
    carried_patterns = {
        str(o.get("pattern")) for o in bundle["objects"] if o.get("type") == "indicator"
    }
    by_key = {_key(str(r.kind or ""), r.value): r for r in rows}
    declines = [why for _code, why in renderer.declined]
    sample = {SHA256, "b" * 40, MD5}

    carried = _bundle_values(bundle)
    for pattern in patterns:
        values = [_key(v.kind, v.value) for v in pattern_values(pattern)]
        if all(v[1] in sample for v in values):
            continue  # names only the sample: folded into the sample's own indicator
        if pattern in carried_patterns:
            # (a) every value of a judge indicator the export carries has a row.
            for found in values:
                assert found in by_key, f"(a) no row for {found} of {pattern}"
        if pattern in carried_patterns or (values and all(v in carried for v in values)):
            # Carried, or merged into an object that names the same values.
            continue
        # (b) declined only for a reason true of it.
        if pattern_problem(pattern) is not None:
            continue
        refused = [
            v
            for v in rule_values(pattern)
            if not publishes(getattr(by_key.get(_key(v.kind, v.value)), "published", None))
        ]
        assert refused, f"(b) {pattern} declined with every value published"
        # The reason names the value (a path by its last component, as findings print it).
        named = [re.split(r"[\\/]", v.value)[-1] for v in refused]
        assert any(n in why for n in named for why in declines), f"(b) {declines}"

    # (c) a sweep row answers as with no judge indicator, the shape's refusal aside.
    if place.startswith("sweep"):
        bare = _report(kind, value, place, verdict, confidence, {"type": "bundle", "objects": []})
        before = {_key(str(r.kind or ""), r.value): r.published for r in ioc_table(bare)}[
            _key(kind, value)
        ]
        after = by_key[_key(kind, value)].published
        if not any(str(before).startswith(f"no: {why}") for why in SHAPE_REFUSALS):
            assert after == before, f"(c) {before!r} -> {after!r}"
        # ... and a value a judge indicator the export accepts names is not asked its shape.
        named = any(
            _key(v.kind, v.value) == _key(kind, value)
            for p in patterns
            if pattern_problem(p) is None
            for v in pattern_values(p)
        )
        if named:
            assert not any(str(after).startswith(f"no: {why}") for why in SHAPE_REFUSALS), (
                f"(c) the judge names it and its shape is asked: {after!r}"
            )

    # (d) a published row's type is that of an object the bundle carries for its value.
    for row in rows:
        if row.source == "identity" or not publishes(row.published) or not row.indicator_type:
            continue
        types = carried.get(_key(str(row.kind or ""), row.value), [])
        assert [row.indicator_type] in types, f"(d) {row.value}: {row.indicator_type} vs {types}"

    # (e) the feed's published set equals the bundle's values, X5 the one exception.
    feed = {
        _key(
            str(r["kind"]), str(r["value"]).split(":", 1)[-1] if r["kind"] == "hash" else r["value"]
        )
        for r in ioc_feed_rows(report.model_dump(mode="json"))
        if r["published"]
    }
    exported = set(carried) | {_key("hash", d) for d in sample}
    # X5: a sweep path whose shape only the judge's naming lifted, the judge's
    # indicator declined: published, and no object of the bundle carries it.
    # The judge's row published by the evidence whose one-value indicator the
    # export declines: no object of the judge's, and none minted for it.
    uncarried = not any(p in carried_patterns for p in patterns)
    exception = (
        {_key(kind, value)}
        if uncarried
        and (
            (label == "path-unshaped" and place == "sweep-second-source")
            or (place in ("nowhere", "second-source") and by_key.get(_key(kind, value)))
        )
        else set()
    )
    assert feed - exported <= exception, f"(e) feed only: {feed - exported}"

    # (g) a value nobody else holds: a row exactly where the judge's naming gives one.
    if place in ("nowhere", "second-source"):
        published_keys_ = {_key(str(r.kind or ""), r.value) for r in rows if publishes(r.published)}
        # The value's own answer, whether or not this case gives it a row: as a
        # one-value indicator naming it alone would have it answered.
        alone = {"type": "bundle", "objects": [_indicator(0, f"[{_comparison(kind, value)}]")]}
        own = {
            _key(str(r.kind or ""), r.value): r.published
            for r in ioc_table(_report(kind, value, place, verdict, confidence, alone))
        }.get(_key(kind, value))
        if publishes(own):
            published_keys_.add(_key(kind, value))

        def _carried(pattern: str) -> bool:
            return pattern_problem(pattern) is None and all(
                _key(v.kind, v.value) in published_keys_ for v in rule_values(pattern)
            )

        naming = [
            p
            for p in patterns
            if _key(kind, value) in {_key(v.kind, v.value) for v in pattern_values(p)}
        ]
        gives = any(len(pattern_values(p)) == 1 or _carried(p) for p in naming)
        assert (_key(kind, value) in by_key) == gives, f"(g) row {_key(kind, value) in by_key}"
        if _key(kind, value) in by_key:
            judge_spellings = {p for p in patterns}
            minted = [
                o["pattern"]
                for o in bundle["objects"]
                if o.get("type") == "indicator"
                and _key(kind, value)
                in {_key(v.kind, v.value) for v in pattern_values(o["pattern"])}
                and o["pattern"] not in judge_spellings
            ]
            assert minted == [], f"(g) minted for a judge row: {minted}"

    # (f) naming through a declined indicator answers the row as naming through a carried one.
    if shape == "declined-only" and place in ("sweep", "sweep-second-source", "host-row"):
        carried_judge = {
            "type": "bundle",
            "objects": [_indicator(0, f"[{_comparison(kind, value)}]")],
        }
        through_carried = ioc_table(_report(kind, value, place, verdict, confidence, carried_judge))
        expected = {_key(str(r.kind or ""), r.value): r.published for r in through_carried}
        assert by_key[_key(kind, value)].published == expected[_key(kind, value)], "(f)"
    assert {k for k in exported - feed if k[0] != "hash"} == set(), f"(e) {exported - feed}"


def test_the_net_is_as_wide_as_it_says() -> None:
    assert len(CASES) == sum(len(PLACES[k]) for k, _v in VALUES.values()) * 11 * len(VERDICTS)


def test_an_unquoted_hash_key_is_read_as_no_value_as_today() -> None:
    """As it is (a registered follow-up): ``file:hashes.MD5`` names no value the reader reads.

    Such an indicator is carried with nothing asked of the digest, and no row
    or feed entry holds the digest.
    """
    pattern = f"[file:hashes.MD5 = '{'d' * 32}']"

    assert pattern_values(pattern) == []
    assert exported_indicator_values({"objects": [_indicator(0, pattern)]}) == []
