"""Lowering must never *broaden* a rule and still call it exact: what cannot be translated
becomes a don't-know (an `unknown(...)` atom or an `unknown("...")` condition part)."""

from __future__ import annotations

from decnique.dsl.format import bundle as fmt_bundle
from decnique.dsl.parser import parse_text
from decnique.eval import fires
from decnique.dsl.ast import Bundle
from decnique.frontends.panther import lower_panther
from decnique.frontends.secops import load_yaral_text
from decnique.model.trace import CAnd, CUnknown


def _yaral(events: str, condition: str) -> object:
    src = f"rule r {{\n  meta:\n    author = \"x\"\n  events:\n{events}\n  condition:\n    {condition}\n}}"
    return load_yaral_text(src, "r.yaral").detections[0]


def test_dropped_conjunct_becomes_unknown_not_true():
    d = _yaral('    $e.metadata.event_type = "X"\n    $e.target.user.userid = $u', "$e and $risk > 50")
    cond = d.spec.condition
    assert isinstance(cond, CAnd) and any(isinstance(x, CUnknown) for x in cond.children)
    # the understood half still constrains; the rule as a whole is "don't know", never "fires"
    assert fires(d.spec, [{"event_type": "X", "udm": {"target.user.userid": "u"}}]) is None
    assert fires(d.spec, [{"event_type": "Y"}]) is False


def test_unparsable_condition_is_unknown_not_true():
    d = _yaral('    $e.metadata.event_type = "X"', "$e and (((")
    assert isinstance(d.spec.condition, CUnknown)
    assert fires(d.spec, [{"event_type": "X"}]) is None
    assert "condition:unparsed:" in " ".join(d.source.unsupported) or "condition:partially_lowered" in d.source.unsupported


def test_same_event_placeholder_equality_is_unknown():
    d = _yaral('    $e.metadata.event_type = "X"\n    $e.principal.ip = $ip\n    $e.target.ip = $ip', "$e")
    assert any(u.startswith("events:same_event_equality") for u in d.source.unsupported)
    assert fires(d.spec, [{"event_type": "X", "udm": {"principal.ip": "1.1.1.1", "target.ip": "2.2.2.2"}}]) is None


def test_cunknown_round_trips_through_the_dsl():
    d = _yaral('    $e.metadata.event_type = "X"', "$e and $risk > 50")
    text = fmt_bundle(Bundle(detections=(d,)))
    assert 'unknown("secops:condition_part")' in text
    assert parse_text(text, "t").detections[0].spec == d.spec


def test_panther_negated_guard_is_read_as_python_not_as_a_literal():
    py = '''
def rule(event):
    if event.deep_get("protoPayload", "methodName") != "SetIamPolicy":
        return False
    return True
'''
    doc = {"AnalysisType": "rule", "RuleID": "r", "LogTypes": ["GCP.AuditLog"], "Enabled": True}
    d, _ = lower_panther(doc, py, "r.yml")
    # `!= X: return False` means "fires only on X" — the evaluator follows the control flow
    assert not d.approximate
    assert fires(d.spec, [{"method": "SetIamPolicy"}]) is True
    assert fires(d.spec, [{"method": "google.iam.admin.v1.CreateServiceAccountKey"}]) is False
    neg, _ = lower_panther(doc, py.replace("!=", "=="), "r.yml")  # now: fires on every OTHER method
    assert fires(neg.spec, [{"method": "SetIamPolicy"}]) is False
    assert fires(neg.spec, [{"method": "google.iam.admin.v1.CreateServiceAccountKey"}]) is True
