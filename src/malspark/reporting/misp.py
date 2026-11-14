"""MISP attributes for a report: its published indicators and techniques, in MISP's own types.

Built deterministically from two things the report already decided: the rows
of its consolidated IOC table the one publish rule publishes, and the ATT&CK
techniques it publishes. Nothing is asked again here, so the attributes carry
exactly what the IOC table, ``/reports/{id}/iocs`` and the STIX export carry:
a withheld row is never an attribute. Each indicator attribute has MISP's
standard type and category for its kind, ``to_ids`` set from the publish
decision, and a comment naming why the row is published and the ledger
entries the table ties to it. An imphash, an ssdeep or a TLSH also matches
files that are not the sample, so it is
published unflagged for IDS. A technique is a ``text`` attribute, tagged with
its ATT&CK galaxy cluster when the vendored ATT&CK table names it, and its
comment names the technique's evidence as every surface prints it
(``technique_evidence``); it describes the sample rather than matching
anything, so it is not flagged for IDS either. Every attribute carries the
report's TLP level as a ``tlp:`` tag.

One pass over the table and one over the techniques; no per-sample value is
written here. ``build_misp_event`` wraps the attributes in one MISP event.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from malspark.core.previous_name import PREVIOUS_NAME
from malspark.reporting.renderers.stix_renderer import digest_label, publishes
from malspark.reporting.stated_host_values import listed_only
from malspark.schemas.stix_models import tlp_name

# The namespace each attribute's uuid is derived in, with the report's own id
# (or its job's) and the attribute's type and value: the same report always
# yields the same uuids, and two reports sharing a value yield two attributes.
# Named under the product's previous name (``malspark.core.previous_name``):
# an attribute a MISP instance already holds keeps its uuid on a re-export.
_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, f"{PREVIOUS_NAME}:misp-attribute")

# The IOC table's digest types, as MISP names the attribute.
_HASH_TYPES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "imphash": "imphash",
    "ssdeep": "ssdeep",
    "tlsh": "tlsh",
}

# The digest types that also match files that are not the sample.
_SIMILARITY_TYPES = frozenset({"imphash", "ssdeep", "tlsh"})

# MISP's attribute type for every other row kind the table holds. A kind MISP
# has no type for is a ``text`` attribute, typed in its comment.
_KIND_TYPES = {
    "domain": "domain",
    "ip": "ip-dst",
    "url": "url",
    "email": "email-dst",
    "user_agent": "user-agent",
    "ja3": "ja3-fingerprint-md5",
    "path": "filename",
    "registry": "regkey",
    "mutex": "mutex",
    "scheduled_task": "windows-scheduled-task",
    "service": "windows-service-name",
    # A value the analysis states and code checked (``stated_host_values``):
    # a registry value is a key path to MISP, and a named pipe has its type.
    # A folder and an alternate data stream have none, and are ``text``.
    "registry_value": "regkey",
    "named_pipe": "named pipe",
}

# The category of a digest, by who recorded the row: the sample's own digests
# deliver the payload, a dropped file's is an artifact, a carved file's
# installs one.
_HASH_CATEGORIES = {
    "identity": "Payload delivery",
    "sandbox": "Artifacts dropped",
    "static": "Payload installation",
}

# The category of every other type, from the categories MISP allows for it.
_TYPE_CATEGORIES = {
    "domain": "Network activity",
    "ip-dst": "Network activity",
    "url": "Network activity",
    "email-dst": "Network activity",
    "user-agent": "Network activity",
    "ja3-fingerprint-md5": "Network activity",
    "filename": "Artifacts dropped",
    "named pipe": "Artifacts dropped",
    "mutex": "Artifacts dropped",
    "windows-scheduled-task": "Artifacts dropped",
    "windows-service-name": "Artifacts dropped",
    "text": "Other",
}


# The categories MISP accepts each type written here in, from PyMISP's
# ``describeTypes.json`` (``category_type_mappings``), restricted to these
# types and to the categories this module chooses.
_ALLOWED_CATEGORIES: dict[str, frozenset[str]] = {
    "md5": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "sha1": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "sha256": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "sha512": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "imphash": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "ssdeep": frozenset({"Payload delivery", "Artifacts dropped", "Payload installation"}),
    "tlsh": frozenset({"Payload delivery", "Payload installation"}),
    "filename": frozenset({"Payload delivery", "Artifacts dropped", "Persistence mechanism"}),
    "named pipe": frozenset({"Artifacts dropped"}),
    "regkey": frozenset({"Artifacts dropped", "Persistence mechanism"}),
    "mutex": frozenset({"Artifacts dropped"}),
    "windows-scheduled-task": frozenset({"Artifacts dropped"}),
    "windows-service-name": frozenset({"Artifacts dropped"}),
}

# The type a row of a kind MISP has no type for is written as; it describes
# and is never flagged for IDS.
_UNTYPED = "text"


def misp_type(row: Any) -> tuple[str, str]:
    """MISP's attribute type and category for one IOC-table row.

    A category MISP does not accept the type in is ``Payload delivery``,
    which accepts every digest and file type this module writes.
    """
    kind, category = _chosen_type(row)
    allowed = _ALLOWED_CATEGORIES.get(kind)
    if allowed is not None and category not in allowed:
        return kind, "Payload delivery"
    return kind, category


def _chosen_type(row: Any) -> tuple[str, str]:
    kind = str(getattr(row, "kind", "") or "")
    label = str(getattr(row, "type", "") or "")
    source = str(getattr(row, "source", "") or "")
    if kind == "hash":
        # The sample's own digests carry the algorithm the router computed;
        # any other digest is named by its length, and none otherwise.
        named = label if source == "identity" else digest_label(getattr(row, "value", ""))
        name = _HASH_TYPES.get(str(named or "").strip().lower().replace("-", ""), "")
        if not name:
            return "", ""
        return name, _HASH_CATEGORIES.get(source, "Payload delivery")
    if kind in ("registry", "registry_value"):
        # A key a persistence mechanism names persists the sample; a key a
        # sandbox, a string sweep or the analysis recorded is an artifact of the run.
        category = "Persistence mechanism" if source == "persistence" else "Artifacts dropped"
        return "regkey", category
    if kind == "path" and label == "Named pipe":
        return "named pipe", _TYPE_CATEGORIES["named pipe"]
    name = _KIND_TYPES.get(kind, "text")
    return name, _TYPE_CATEGORIES.get(name, "Other")


def misp_owner(report: Any, job_id: Any = None) -> str:
    """What a report's attribute uuids are derived from: its job's id, else its own number."""
    front = getattr(report, "front_matter", None)
    number = str(getattr(front, "report_number", "") or "") if front is not None else ""
    hashes = getattr(getattr(report, "identity", None), "hashes", None)
    return str(job_id or number or getattr(hashes, "sha256", "") or "")


def _reason(answer: Any) -> str:
    text = str(answer or "").strip()
    return text.split(":", 1)[1].strip() if ":" in text else ""


def row_evidence(row: Any) -> list[str]:
    """The ledger ids an IOC-table row carries (``ConsolidatedIOC.evidence_ids``)."""
    return [str(i) for i in getattr(row, "evidence_ids", None) or []]


def build_misp_attributes(
    report: Any, rows: Iterable[Any] | None = None, *, owner: str
) -> list[dict[str, Any]]:
    """The report's MISP attributes: one per published IOC-table row, then one per technique.

    ``rows`` is the report's IOC table; the stored one when not given. A row
    the publish rule withholds is not an attribute, and neither is a digest
    whose length names no algorithm. Each (type, value) is written once, in
    the table's order. ``owner`` is the report's id, or its job's, which each
    attribute's uuid is derived from.
    """
    from malspark.memory.attck_loader import technique_entry
    from malspark.reporting.detonation_marks import observed_words
    from malspark.reporting.technique_evidence import (
        technique_evidence_ids,
        technique_evidence_words,
    )

    table = list(rows if rows is not None else getattr(report, "consolidated_iocs", None) or [])
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    # The report's TLP level as MISP's ``tlp`` taxonomy tags it (``tlp:amber``),
    # on every attribute; none when the report holds no level.
    level = tlp_name(str(getattr(report, "tlp", "") or ""))
    tlp_tags = [{"name": level.lower()}] if level else []

    def _attribute(kind: str, category: str, value: str, to_ids: bool, comment: str) -> dict:
        attribute: dict[str, Any] = {
            "uuid": str(uuid.uuid5(_NAMESPACE, f"{owner}|{kind}|{value}")),
            "type": kind,
            "category": category,
            "value": value,
            "to_ids": to_ids,
            "comment": comment,
        }
        if tlp_tags:
            attribute["Tag"] = list(tlp_tags)
        return attribute

    for row in table:
        value = str(getattr(row, "value", "") or "").strip()
        answer = getattr(row, "published", None)
        if not value or not publishes(answer):
            continue
        kind, category = misp_type(row)
        if not kind:
            continue
        key = (kind, value.lower())
        if key in seen:
            continue
        seen.add(key)
        label = str(getattr(row, "type", "") or "")
        why = _reason(answer)
        cited = row_evidence(row)
        comment = "; ".join(
            part
            for part in (
                label if kind == "text" else "",
                str(getattr(row, "context", "") or ""),
                f"published because {why}" if why else "",
                # The ledger entries the table ties to the row, which MISP has
                # no field for: named in the comment.
                f"evidence {', '.join(cited)}" if cited else "",
                # Under which detonations it was observed, where a further
                # detonation an agent asked for observed it: in the comment too.
                observed_words(getattr(row, "observed_in", None) or ()),
            )
            if part
        )
        # A generic name is listed, never matched on alone (``listed_only``).
        to_ids = (
            publishes(answer)
            and kind not in _SIMILARITY_TYPES
            and kind != _UNTYPED
            and not listed_only(answer)
        )
        out.append(_attribute(kind, category, value, to_ids, comment))

    techniques: set[str] = set()
    for mapping in getattr(report, "ttp_mappings", None) or []:
        tid = str(getattr(mapping, "technique_id", "") or "").strip().upper()
        if not tid or tid in techniques:
            continue
        techniques.add(tid)
        # The galaxy cluster is named as ATT&CK names the technique, from the
        # vendored table; a technique the table does not name gets no tag.
        entry = technique_entry(tid)
        canonical = str(getattr(entry, "name", "") or "").strip() if entry is not None else ""
        name = canonical or str(getattr(mapping, "technique_name", "") or "").strip()
        attribute = _attribute(
            "text",
            "External analysis",
            f"{tid} {name}" if name else tid,
            False,
            "; ".join(
                part
                for part in (
                    "ATT&CK technique this report publishes",
                    # A mapping stored before its evidence was recorded, and
                    # naming no entry, says nothing either way.
                    f"evidence: {technique_evidence_words(mapping)}"
                    if technique_evidence_ids(mapping) is not None
                    else "",
                    observed_words(getattr(mapping, "observed_in", None) or ()),
                )
                if part
            ),
        )
        if canonical:
            attribute["Tag"] = [
                *tlp_tags,
                {"name": f'misp-galaxy:mitre-attack-pattern="{canonical} - {tid}"'},
            ]
        out.append(attribute)
    return out


# The namespace an event's uuid is derived in, with what its attributes' uuids
# are derived from (``misp_owner``): one report is one event in every export.
_EVENT_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "malspark:misp-event")

# MISP's ``file`` object template, as the MISP object library publishes it.
_FILE_TEMPLATE = "688c46fb-5edb-40a3-8273-1af7923e2215"
_FILE_TEMPLATE_VERSION = "25"

# The sample's identity digests, as the file object's relations name them.
_FILE_DIGESTS = (
    ("md5", "md5"),
    ("sha1", "sha1"),
    ("sha256", "sha256"),
    ("sha512", "sha512"),
    ("imphash", "imphash"),
    ("ssdeep", "ssdeep"),
    ("tlsh", "tlsh"),
)


def build_misp_event(report: Any, attributes: Iterable[dict[str, Any]], *, owner: str) -> dict:
    """The report as one MISP event: ``{"Event": ...}``, from what the report already holds.

    ``attributes`` are the report's published MISP attributes
    (:func:`build_misp_attributes`), carried as they are. The event's uuid is
    derived from ``owner``, as the attributes' are, and its date is the day
    the report was built, so one report is one event in every export. The
    analysis is complete (2) and the distribution is the organisation only
    (0): the receiver decides how far it shares. The threat level is
    undefined (4): no field of the report maps to MISP's levels one to one.
    The tags are the report's TLP level, its verdict and the ATT&CK galaxy
    clusters its technique attributes carry, each where the report holds it,
    and a ``file`` object names the sample by its name, its size and the
    digests its identity holds that no attribute of the event carries already.
    """
    identity = getattr(report, "identity", None)
    hashes = getattr(identity, "hashes", None)
    sha256 = str(getattr(hashes, "sha256", "") or "")
    built = getattr(report, "generated_at", None)
    carried = [dict(attribute) for attribute in attributes]

    tags: list[dict[str, str]] = []
    level = tlp_name(str(getattr(report, "tlp", "") or ""))
    if level:
        tags.append({"name": level.lower()})
    verdict = str(getattr(report, "verdict", "") or "").strip()
    if verdict:
        tags.append({"name": f'malspark:verdict="{verdict}"'})
    for attribute in carried:
        for tag in attribute.get("Tag") or []:
            name = str(tag.get("name") or "")
            if name.startswith("misp-galaxy:") and {"name": name} not in tags:
                tags.append({"name": name})

    event: dict[str, Any] = {
        "uuid": str(uuid.uuid5(_EVENT_NAMESPACE, owner)),
        "info": f"Malspark analysis of {sha256[:12] if sha256 else 'sample'}",
        "date": built.date().isoformat() if built is not None else None,
        "analysis": "2",
        "distribution": "0",
        "threat_level_id": "4",
        "Tag": tags,
        "Attribute": carried,
    }
    if event["date"] is None:
        del event["date"]
    sample = _file_object(identity, owner, carried)
    if sample is not None:
        event["Object"] = [sample]
    return {"Event": event}


def _file_object(
    identity: Any, owner: str, attributes: Iterable[dict[str, Any]] = ()
) -> dict[str, Any] | None:
    """MISP's ``file`` object for the sample: its name, size and identity digests, as held.

    A digest one of the event's ``attributes`` carries (same type, same value)
    is not repeated in the object: MISP would hold it twice. ``None`` when the
    identity holds no digest at all, or the object would name nothing.
    """
    hashes = getattr(identity, "hashes", None)
    carried = {
        (str(a.get("type") or ""), str(a.get("value") or "").strip().lower()) for a in attributes
    }
    held = False
    relations: list[tuple[str, str, str, bool]] = []
    for relation, field in _FILE_DIGESTS:
        value = str(getattr(hashes, field, "") or "").strip()
        if not value:
            continue
        held = True
        if (relation, value.lower()) not in carried:
            relations.append((relation, relation, value, relation not in _SIMILARITY_TYPES))
    if not held:
        return None
    name = str(getattr(identity, "file_name", "") or "").strip()
    if name:
        relations.append(("filename", "filename", name, False))
    size = getattr(identity, "file_size_bytes", None)
    if isinstance(size, int) and size > 0:
        relations.append(("size-in-bytes", "size-in-bytes", str(size), False))
    if not relations:
        return None
    return {
        "uuid": str(uuid.uuid5(_EVENT_NAMESPACE, f"{owner}|file")),
        "name": "file",
        "meta-category": "file",
        "template_uuid": _FILE_TEMPLATE,
        "template_version": _FILE_TEMPLATE_VERSION,
        "Attribute": [
            {
                "uuid": str(uuid.uuid5(_EVENT_NAMESPACE, f"{owner}|file|{relation}|{value}")),
                "object_relation": relation,
                "type": kind,
                # MISP files a size under "Other", every other relation here
                # under "Payload delivery".
                "category": "Other" if kind == "size-in-bytes" else "Payload delivery",
                "value": value,
                "to_ids": to_ids,
            }
            for relation, kind, value, to_ids in relations
        ],
    }
