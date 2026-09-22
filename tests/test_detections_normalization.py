"""Real Cloud Audit Log replay must retain the structured fields IAM detections inspect."""

from decnique.detections import DetectionLibrary, event_from_audit_log, to_audit_log
from decnique.dsl.parser import parse_text

_BINDING = "target.resource.attribute.labels[ser_binding_deltas_%s]"
_AUDIT = (
    "target.resource.attribute.labels["
    "service_data_policy_delta_audit_config_delta_%s]"
)


def _entry():
    return {
        "timestamp": "2026-08-30T10:00:00Z",
        "logName": "projects/demo/logs/cloudaudit.googleapis.com%2Factivity",
        "resource": {
            "type": "audited_resource",
            "labels": {"project_id": "demo", "location": "europe-west1"},
        },
        "protoPayload": {
            "methodName": "SetIamPolicy",
            "serviceName": "cloudresourcemanager.googleapis.com",
            "authenticationInfo": {"principalEmail": "ADMIN@EXAMPLE.COM"},
            "authorizationInfo": [
                {
                    "permission": "resourcemanager.projects.setIamPolicy",
                    "granted": True,
                    "resource": "projects/demo",
                    "resourceAttributes": {"type": "cloudresourcemanager.googleapis.com/Project"},
                },
                {
                    "permission": "resourcemanager.projects.getIamPolicy",
                    "granted": False,
                    "resource": "projects/other",
                    "resourceAttributes": {"type": "cloudresourcemanager.googleapis.com/Project"},
                },
            ],
            "requestMetadata": {
                "callerIp": "203.0.113.10",
                "callerSuppliedUserAgent": "gcloud",
                "requestAttributes": {"auth": {"accessLevels": ["trusted", "corp"]}},
            },
            "request": {
                "policy": {
                    "bindings": [
                        {"role": "roles/owner", "members": ["user:bob@example.com"]},
                        {"role": "roles/viewer", "members": ["group:dev@example.com"]},
                    ]
                },
                "etag": "BwY=",
            },
            "status": {"code": 7, "message": "permission denied", "details": ["policy"]},
            "serviceData": {
                "policyDelta": {
                    "bindingDeltas": [
                        {"action": "ADD", "role": "roles/owner", "member": "user:bob@example.com"},
                        {"action": "REMOVE", "role": "roles/viewer", "member": "group:old@example.com"},
                    ],
                    "auditConfigDeltas": [
                        {
                            "action": "ADD",
                            "service": "storage.googleapis.com",
                            "logType": "DATA_READ",
                            "exemptedMember": "user:quiet@example.com",
                        },
                        {
                            "action": "REMOVE",
                            "service": "bigquery.googleapis.com",
                            "logType": "DATA_WRITE",
                            "exemptedMember": "group:legacy@example.com",
                        },
                    ],
                }
            },
        },
    }


def test_normalizer_preserves_iam_replay_fields():
    event = event_from_audit_log(_entry())

    assert event["principal"] == "admin@example.com"
    assert event["permission"] == [
        "resourcemanager.projects.setIamPolicy",
        "resourcemanager.projects.getIamPolicy",
    ]
    assert event["granted"] == [True, False]
    assert event["resource"] == ["projects/demo", "projects/other"]
    assert event["resource_type"] == [
        "cloudresourcemanager.googleapis.com/Project",
        "cloudresourcemanager.googleapis.com/Project",
    ]
    assert event["project"] == "demo"
    assert event["access_levels"] == ["trusted", "corp"]

    udm = event["udm"]
    assert udm[_BINDING % "action"] == ["ADD", "REMOVE"]
    assert udm[_BINDING % "role"] == ["roles/owner", "roles/viewer"]
    assert udm[_BINDING % "member"] == [
        "user:bob@example.com",
        "group:old@example.com",
    ]
    assert udm[_AUDIT % "action"] == ["ADD", "REMOVE"]
    assert udm[_AUDIT % "service"] == [
        "storage.googleapis.com",
        "bigquery.googleapis.com",
    ]
    assert udm[_AUDIT % "log_type"] == ["DATA_READ", "DATA_WRITE"]
    assert udm[_AUDIT % "exempted_member"] == [
        "user:quiet@example.com",
        "group:legacy@example.com",
    ]
    assert udm["protoPayload.request.policy.bindings.role"] == [
        "roles/owner",
        "roles/viewer",
    ]
    assert udm["protoPayload.status.code"] == 7
    assert udm["protoPayload.status.message"] == "permission denied"
    assert udm["resource.labels.project_id"] == "demo"
    assert udm["resource.labels.location"] == "europe-west1"
    assert udm["protoPayload.authorizationInfo.permission"] == event["permission"]


def test_owner_delta_survives_ingest_and_fires_rule():
    event = event_from_audit_log(_entry())
    lib = DetectionLibrary(
        parse_text(
            'detection owner { event method = "SetIamPolicy" '
            'and udm("target.resource.attribute.labels[ser_binding_deltas_action]") = "ADD" '
            'and udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner" '
            'and udm("target.resource.attribute.labels[ser_binding_deltas_member]") '
            'startswith "user:" }',
            "owner.decn",
        )
    )

    assert lib.observing(event).observed_by == ("owner",)


def test_repeated_policy_deltas_round_trip_to_raw_audit_log():
    event = event_from_audit_log(_entry())

    raw = to_audit_log(event)

    policy_delta = raw["protoPayload"]["serviceData"]["policyDelta"]
    assert policy_delta["bindingDeltas"] == _entry()["protoPayload"]["serviceData"][
        "policyDelta"
    ]["bindingDeltas"]
    assert policy_delta["auditConfigDeltas"] == _entry()["protoPayload"]["serviceData"][
        "policyDelta"
    ]["auditConfigDeltas"]
    back = event_from_audit_log(raw)
    assert back["udm"][_BINDING % "role"] == ["roles/owner", "roles/viewer"]
    assert back["udm"][_AUDIT % "service"] == [
        "storage.googleapis.com",
        "bigquery.googleapis.com",
    ]
