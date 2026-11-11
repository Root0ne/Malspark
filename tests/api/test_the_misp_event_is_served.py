"""``/reports/{id}/misp-event`` serves the report as one MISP event.

The platform built MISP attributes and no event: the console saved a bare
attribute array a MISP instance does not import as it stands. The event wraps
the report's published attributes with a uuid derived from the report's job,
as the attributes' own are, so a second request is the same event, and leaves
how far it is shared to the receiver (distribution 0).

Driven through the route, so the response is what a client reads.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import reports as module
from malspark.core.previous_name import PREVIOUS_NAME

REPORT_ID = uuid.uuid4()
JOB_ID = uuid.uuid4()
SHA256 = "f" * 64
ATTRIBUTE = {
    "uuid": "00000000-0000-5000-8000-000000000001",
    "type": "sha256",
    "category": "Payload delivery",
    "value": SHA256,
    "to_ids": True,
    "comment": "the sample",
    "Tag": [{"name": "tlp:amber"}],
}
TECHNIQUE = {
    "uuid": "00000000-0000-5000-8000-000000000002",
    "type": "text",
    "category": "External analysis",
    "value": "T1059 Command and Scripting Interpreter",
    "to_ids": False,
    "comment": "ATT&CK technique this report publishes",
    "Tag": [
        {"name": "tlp:amber"},
        {"name": 'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"'},
    ],
}


def _malware_report(**over: Any) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-05-16T08:30:00+00:00",
        "verdict": "Malware",
        "tlp": "AMBER",
        "identity": {
            "hashes": {"sha256": SHA256, "md5": "d" * 32},
            "file_name": "sample.exe",
            "file_size_bytes": 2048,
            "file_type": "PE",
            "signing": {"is_signed": False},
        },
        "executive_summary": "",
        "misp_attributes": [ATTRIBUTE, TECHNIQUE],
        **over,
    }


def _client(
    stored: dict[str, Any] | None, report_id: uuid.UUID = REPORT_ID, job_id: uuid.UUID = JOB_ID
) -> TestClient:
    from app.database import get_db
    from app.deps import get_current_user, require_active_user

    report = MagicMock()
    report.id = report_id
    report.job_id = job_id
    report.malware_report = stored
    service = module.ReportService(db=AsyncMock())
    service.get_report = AsyncMock(return_value=report)  # type: ignore[method-assign]
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    user = MagicMock(id=uuid.uuid4(), email="op@example.com")
    app.dependency_overrides[get_db] = lambda: AsyncMock()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_active_user] = lambda: user
    app.dependency_overrides[module._get_service] = lambda: service
    return TestClient(app)


def test_the_event_wraps_the_published_attributes() -> None:
    response = _client(_malware_report()).get(f"/api/v1/reports/{REPORT_ID}/misp-event")

    assert response.status_code == 200, response.text
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "malspark:misp-event")
    owner = str(JOB_ID)
    file_attribute = {
        "object_relation": "",
        "type": "",
        "category": "Payload delivery",
        "value": "",
        "to_ids": True,
    }
    expected_file = [
        {**file_attribute, "object_relation": rel, "type": rel, "value": value, "to_ids": ids,
         "category": category,
         "uuid": str(uuid.uuid5(namespace, f"{owner}|file|{rel}|{value}"))}
        for rel, value, ids, category in (
            # The sha256 is an attribute of the event already: not repeated.
            ("md5", "d" * 32, True, "Payload delivery"),
            ("filename", "sample.exe", False, "Payload delivery"),
            ("size-in-bytes", "2048", False, "Other"),
        )
    ]  # fmt: skip
    assert response.json() == {
        "Event": {
            "uuid": str(uuid.uuid5(namespace, owner)),
            "info": "Malspark analysis of ffffffffffff",
            "date": "2026-05-16",
            "analysis": "2",
            "distribution": "0",
            "threat_level_id": "4",
            "Tag": [
                {"name": "tlp:amber"},
                {"name": 'malspark:verdict="Malware"'},
                {
                    "name": (
                        'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - '
                        'T1059"'
                    )
                },
            ],
            "Attribute": [ATTRIBUTE, TECHNIQUE],
            "Object": [
                {
                    "uuid": str(uuid.uuid5(namespace, f"{owner}|file")),
                    "name": "file",
                    "meta-category": "file",
                    "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
                    "template_version": "25",
                    "Attribute": expected_file,
                }
            ],
        }
    }


def test_a_second_request_is_the_same_event() -> None:
    client = _client(_malware_report())

    first = client.get(f"/api/v1/reports/{REPORT_ID}/misp-event")
    second = client.get(f"/api/v1/reports/{REPORT_ID}/misp-event")

    assert (first.status_code, second.status_code) == (200, 200)
    assert first.json() == second.json()


def test_a_report_stored_before_its_attributes_is_one_owner_s_event() -> None:
    # The attributes are built when served, under the report's id; the
    # event's uuid is derived from the same id, not from the job's.
    report_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    job_id = uuid.UUID("22222222-2222-4222-8222-222222222222")
    stored = _malware_report(misp_attributes=None)
    client = _client(stored, report_id=report_id, job_id=job_id)

    response = client.get(f"/api/v1/reports/{report_id}/misp-event")

    assert response.status_code == 200, response.text
    events = uuid.uuid5(uuid.NAMESPACE_URL, "malspark:misp-event")
    attributes = uuid.uuid5(uuid.NAMESPACE_URL, f"{PREVIOUS_NAME}:misp-attribute")
    # The recipes, restated: both from the report's id.
    assert str(uuid.uuid5(events, str(report_id))) == "499775dc-79f4-54da-8f29-2432d2b0ddd0"
    assert (
        str(uuid.uuid5(attributes, f"{report_id}|sha256|{SHA256}"))
        == "d2df177d-ef50-5614-8dd7-1c7c5bae89f8"
    )
    digest = {
        "category": "Payload delivery",
        "to_ids": True,
        "comment": "the sample; published because the sample's own digest",
        "Tag": [{"name": "tlp:amber"}],
    }
    size_and_name = {"category": "Payload delivery", "to_ids": False}
    assert response.json() == {
        "Event": {
            "uuid": "499775dc-79f4-54da-8f29-2432d2b0ddd0",
            "info": "Malspark analysis of ffffffffffff",
            "date": "2026-05-16",
            "analysis": "2",
            "distribution": "0",
            "threat_level_id": "4",
            "Tag": [{"name": "tlp:amber"}, {"name": 'malspark:verdict="Malware"'}],
            "Attribute": [
                {
                    "uuid": "d2df177d-ef50-5614-8dd7-1c7c5bae89f8",
                    "type": "sha256",
                    "value": SHA256,
                    **digest,
                },
                {
                    "uuid": "3feda721-8542-5774-99e3-833dcffb6228",
                    "type": "md5",
                    "value": "d" * 32,
                    **digest,
                },
            ],
            "Object": [
                {
                    "uuid": "ad21c44b-393a-55b0-bb6d-e7dff4c400e8",
                    "name": "file",
                    "meta-category": "file",
                    "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
                    "template_version": "25",
                    # Both digests are attributes of the event: the object
                    # names the file and its size only.
                    "Attribute": [
                        {
                            **size_and_name,
                            "uuid": "6c47794c-e2ff-5a92-b184-6437dd805463",
                            "object_relation": "filename",
                            "type": "filename",
                            "value": "sample.exe",
                        },
                        {
                            **size_and_name,
                            "uuid": "2988344f-9e4d-5ebc-8481-cef1a7bbcbfc",
                            "object_relation": "size-in-bytes",
                            "type": "size-in-bytes",
                            "category": "Other",
                            "value": "2048",
                        },
                    ],
                }
            ],
        }
    }


def test_a_galaxy_cluster_two_attributes_carry_is_one_event_tag() -> None:
    again = {**TECHNIQUE, "uuid": "00000000-0000-5000-8000-000000000003", "value": "T1059"}
    client = _client(_malware_report(misp_attributes=[ATTRIBUTE, TECHNIQUE, again]))

    response = client.get(f"/api/v1/reports/{REPORT_ID}/misp-event")

    assert response.status_code == 200, response.text
    assert response.json()["Event"]["Tag"] == [
        {"name": "tlp:amber"},
        {"name": 'malspark:verdict="Malware"'},
        {"name": 'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"'},
    ]


def _hashes_only(**hashes: str) -> dict[str, Any]:
    return {
        "identity": {
            "hashes": hashes,
            "file_name": "",
            "file_size_bytes": 0,
            "file_type": "PE",
            "signing": {"is_signed": False},
        }
    }


def test_a_file_object_that_would_name_nothing_is_left_out() -> None:
    # Both digests the identity holds are attributes of the event already, and
    # it holds no file name and no size: the object would be empty.
    md5 = {**ATTRIBUTE, "type": "md5", "value": "d" * 32}
    response = _client(
        _malware_report(
            misp_attributes=[ATTRIBUTE, md5], **_hashes_only(sha256=SHA256, md5="d" * 32)
        )
    ).get(f"/api/v1/reports/{REPORT_ID}/misp-event")

    assert response.status_code == 200, response.text
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "malspark:misp-event")
    assert response.json() == {
        "Event": {
            "uuid": str(uuid.uuid5(namespace, str(JOB_ID))),
            "info": "Malspark analysis of ffffffffffff",
            "date": "2026-05-16",
            "analysis": "2",
            "distribution": "0",
            "threat_level_id": "4",
            "Tag": [{"name": "tlp:amber"}, {"name": 'malspark:verdict="Malware"'}],
            "Attribute": [ATTRIBUTE, md5],
        }
    }


def test_digests_differing_only_in_letter_case_are_one_digest() -> None:
    # The event carries the md5 in upper case; the identity holds it in lower.
    md5 = {**ATTRIBUTE, "type": "md5", "value": "D" * 32}
    response = _client(
        _malware_report(
            misp_attributes=[ATTRIBUTE, md5],
            identity={
                "hashes": {"sha256": SHA256, "md5": "d" * 32, "sha1": "e" * 40},
                "file_name": "",
                "file_size_bytes": 0,
                "file_type": "PE",
                "signing": {"is_signed": False},
            },
        )
    ).get(f"/api/v1/reports/{REPORT_ID}/misp-event")

    assert response.status_code == 200, response.text
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "malspark:misp-event")
    owner = str(JOB_ID)
    assert response.json()["Event"]["Object"] == [
        {
            "uuid": str(uuid.uuid5(namespace, f"{owner}|file")),
            "name": "file",
            "meta-category": "file",
            "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
            "template_version": "25",
            "Attribute": [
                {
                    "uuid": str(uuid.uuid5(namespace, f"{owner}|file|sha1|{'e' * 40}")),
                    "object_relation": "sha1",
                    "type": "sha1",
                    "category": "Payload delivery",
                    "value": "e" * 40,
                    "to_ids": True,
                }
            ],
        }
    ]
