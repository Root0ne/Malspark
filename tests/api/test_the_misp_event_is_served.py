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


def _client(stored: dict[str, Any] | None) -> TestClient:
    from app.database import get_db
    from app.deps import get_current_user, require_active_user

    report = MagicMock()
    report.id = REPORT_ID
    report.job_id = JOB_ID
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
            ("md5", "d" * 32, True, "Payload delivery"),
            ("sha256", SHA256, True, "Payload delivery"),
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
