"""Panther rule() bodies are evaluated symbolically: control flow, reads, loops, helpers —
and anything else is an explicit don't-know."""

from __future__ import annotations

from decnique.dsl.interpret import evaluate
from decnique.frontends.panther_py import rule_predicate
from decnique.model.predicates import Unknown, unknowns

_D = "target.resource.attribute.labels[ser_binding_deltas_%s]"  # bare path under event["udm"]


def _ev(**kw):
    e = {"method": "SetIamPolicy", "principal": "a@x.com", "granted": True, "permission": ["p"], "udm": {}}
    e.update(kw)
    return e


def _pred(src: str):
    p, missing = rule_predicate(src)
    return p, missing


def test_guards_loops_and_constants():
    src = '''
METHODS = ("dns.changes.create", "dns.managedZones.delete")
def rule(event):
    if event.get("severity") == "ERROR":
        return False
    if event.deep_get("protoPayload", "methodName", default="") not in METHODS:
        return False
    for auth in event.deep_walk("protoPayload", "authorizationInfo"):
        if auth.get("permission") == "dns.changes.create" and auth.get("granted") is True:
            return True
    return False
'''
    p, missing = _pred(src)
    assert not missing and not unknowns(p)
    ok = _ev(method="dns.changes.create", permission=["dns.changes.create"])
    assert evaluate(p, ok) is True
    assert evaluate(p, _ev(method="dns.changes.create", permission=["dns.changes.create"], udm={"severity": "ERROR"})) is False
    assert evaluate(p, _ev(method="other", permission=["dns.changes.create"])) is False
    assert evaluate(p, _ev(method="dns.changes.create", permission=["dns.changes.create"], granted=False)) is False


def test_any_all_endswith_regex_and_helpers():
    src = '''
import re
PATTERN = re.compile(r"v\\d\\.ConfigServiceV\\d\\.UpdateSink")
def _robot(event):
    return event.deep_get("protoPayload", "authenticationInfo", "principalEmail", default="").endswith(".gserviceaccount.com")
def rule(event):
    granted = event.deep_walk("protoPayload", "authorizationInfo", "granted", default=[])
    authenticated = any(granted) if isinstance(granted, list) else bool(granted)
    return all([
        authenticated,
        PATTERN.search(event.deep_get("protoPayload", "methodName", default="")) is not None,
        not _robot(event),
        "logging" in event.deep_get("protoPayload", "serviceName", default=""),
    ])
'''
    p, missing = _pred(src)
    assert not missing and not unknowns(p)
    good = _ev(method="google.logging.v2.ConfigServiceV2.UpdateSink", service="logging.googleapis.com")
    assert evaluate(p, good) is True
    assert evaluate(p, {**good, "principal": "sa@p.iam.gserviceaccount.com"}) is False
    assert evaluate(p, {**good, "method": "google.logging.v2.ConfigServiceV2.DeleteSink"}) is False
    assert evaluate(p, {**good, "granted": False}) is False


def test_binding_deltas_and_data_model():
    src = '''
from panther_gcp_helpers import get_binding_deltas
def rule(event):
    for delta in get_binding_deltas(event):
        if delta.get("action") == "ADD" and delta.get("role") in ("roles/owner", "roles/editor"):
            return True
    return False
'''
    p, missing = _pred(src)
    assert not missing
    assert evaluate(p, _ev(udm={_D % "action": "ADD", _D % "role": "roles/editor"})) is True
    assert evaluate(p, _ev(udm={_D % "action": "REMOVE", _D % "role": "roles/editor"})) is False
    dm, missing = _pred('def rule(event):\n    return event.udm("event_type") == event_type.ADMIN_ROLE_ASSIGNED\n')
    assert not missing
    assert evaluate(dm, _ev(udm={_D % "action": "ADD", _D % "role": "roles/owner"})) is True
    assert evaluate(dm, _ev(udm={_D % "action": "ADD", _D % "role": "roles/viewer"})) is False
    other, _ = _pred('def rule(event):\n    return event.udm("event_type") == event_type.FAILED_LOGIN\n')
    assert evaluate(other, _ev()) is False  # the GCP data model never yields it


def test_unsupported_construct_is_an_explicit_dont_know():
    src = '''
def rule(event):
    if event.deep_get("protoPayload", "methodName") != "storage.objects.get":
        return False
    parts = event.deep_get("protoPayload", "resourceName", default="").split("/")
    return parts[-1] == "secret"
'''
    p, missing = _pred(src)
    assert missing == ["str.split"]
    u = unknowns(p)
    assert u and u[0].label == "panther:python:str.split" and u[0].fields == ((None, "resource"),)
    assert evaluate(p, _ev(method="storage.objects.get", resource="b/o/secret")) is None  # don't know
    assert evaluate(p, _ev(method="SetIamPolicy")) is False  # the understood guard still decides
