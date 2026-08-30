"""The audit-log projector must turn a log ``timestamp`` into the model's ``time`` field
(epoch seconds), so correlation windows / footprint spans can be evaluated.  Both the
RFC 3339 string form and an already-epoch value are accepted, and it round-trips."""

from decnique.detections import event_from_audit_log, to_audit_log


def _entry(ts):
    return {
        "timestamp": ts,
        "protoPayload": {
            "methodName": "SetIamPolicy",
            "serviceName": "cloudresourcemanager.googleapis.com",
            "authenticationInfo": {"principalEmail": "a@b.com"},
            "authorizationInfo": [{"permission": "resourcemanager.projects.setIamPolicy", "granted": True}],
        },
    }


def test_rfc3339_timestamp_becomes_epoch_time():
    e = event_from_audit_log(_entry("2026-08-30T10:00:00Z"))
    assert e["time"] == 1788084000  # 2026-08-30T10:00:00Z


def test_numeric_timestamp_kept():
    assert event_from_audit_log(_entry(1788084000))["time"] == 1788084000
    assert event_from_audit_log(_entry("1788084000"))["time"] == 1788084000


def test_fractional_and_offset_timestamp():
    a = event_from_audit_log(_entry("2026-08-30T12:00:00.500+02:00"))["time"]
    assert a == 1788084000  # 12:00+02:00 == 10:00Z


def test_missing_or_bad_timestamp_leaves_no_time():
    assert "time" not in event_from_audit_log(_entry(None))
    assert "time" not in event_from_audit_log(_entry("not-a-date"))


def test_time_round_trips_through_audit_log():
    e = event_from_audit_log(_entry("2026-08-30T10:00:00Z"))
    back = event_from_audit_log(to_audit_log(e))
    assert back["time"] == e["time"]
