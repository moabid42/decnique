"""SecOps front-end: translating the common YARA-L string/regex functions exactly.

Rules routinely case-fold a field before matching it (``strings.contains(strings.to_lower($f),
"x")``).  That nested ``to_lower``/``to_upper`` is exactly a case-insensitive match, which the
predicate model represents directly — so it must translate to an exact ``StrFn``/``Regex`` with
``nocase`` rather than degrading the whole rule to *approximate*.
"""

from __future__ import annotations

from decnique.frontends.secops import load_yaral_text
from decnique.model.predicates import Pred, Regex, StrFn, unknowns


def _leaves(p: Pred) -> list[Pred]:
    kids = getattr(p, "children", None)
    if kids is not None:
        return [x for c in kids for x in _leaves(c)]
    child = getattr(p, "child", None)
    if child is not None:
        return _leaves(child)
    return [p]


_RULE = """
rule nested_case_functions {
  meta:
    author = "test"
  events:
    $e.metadata.product_name = "Google Cloud IAM"
    strings.contains(strings.to_lower($e.principal.user.userid), "admin")
    re.regex(strings.to_lower($e.target.application), ".*token.*")
  condition:
    $e
}
"""


def _pred() -> Pred:
    d = load_yaral_text(_RULE, "nested.yaral").detections[0]
    assert not d.approximate, d.source.unsupported if d.source else ()
    return d.spec.events[0].pred


def test_nested_to_lower_is_exact_not_approximate():
    leaves = _leaves(_pred())
    assert all(not unknowns(leaf) for leaf in leaves)


def test_nested_to_lower_becomes_case_insensitive_strfn():
    strfns = [leaf for leaf in _leaves(_pred()) if isinstance(leaf, StrFn)]
    assert strfns and all(s.nocase for s in strfns)
    assert any(s.fn == "contains" and s.value == "admin" for s in strfns)


def test_nested_to_lower_becomes_case_insensitive_regex():
    regexes = [leaf for leaf in _leaves(_pred()) if isinstance(leaf, Regex)]
    assert regexes and all(r.nocase for r in regexes)


# --- Panther standard rules over the GCP data model ---------------------------------------


def test_panther_datamodel_admin_role_assigned_is_exact():
    from decnique.frontends.panther import _datamodel_pred
    from decnique.dsl.interpret import evaluate
    from decnique.model.predicates import Unknown

    py = 'def rule(event):\n    return event.udm("event_type") == event_type.ADMIN_ROLE_ASSIGNED\n'
    p = _datamodel_pred(py)
    assert p is not None and not any(isinstance(x, Unknown) for x in [p])
    L = "target.resource.attribute.labels[ser_binding_deltas_%s]"
    owner_to_user = {"method": "SetIamPolicy", "udm": {L % "action": "ADD", L % "role": "roles/owner"}}
    admin_role = {"method": "SetIamPolicy", "udm": {L % "action": "ADD", L % "role": "roles/iam.securityAdmin"}}
    viewer = {"method": "SetIamPolicy", "udm": {L % "action": "ADD", L % "role": "roles/viewer"}}
    assert evaluate(p, owner_to_user) is True
    assert evaluate(p, admin_role) is True
    assert evaluate(p, viewer) is False
    # any other data-model event type is never produced for GCP audit logs → exact false
    q = _datamodel_pred('def rule(event):\n    return event.udm("event_type") == event_type.FAILED_LOGIN\n')
    assert evaluate(q, owner_to_user) is False


# --- honesty: a rule with no recognised event variable is unknown, never true ----------------


def test_inline_section_header_is_parsed():
    from decnique.dsl.interpret import observes
    from decnique.frontends.secops import load_yaral_text

    r = 'rule r { meta: author = "x" events: $e.metadata.event_type = "USER_LOGIN" condition: $e }'
    d = load_yaral_text(r, "r.yaral").detections[0]
    assert not d.source.unsupported
    assert observes(d, {"event_type": "USER_LOGIN"}) is True
    assert observes(d, {"event_type": "OTHER"}) is False


def test_no_event_variable_is_unknown_not_true():
    from decnique.dsl.interpret import observes
    from decnique.frontends.secops import load_yaral_text

    r = "rule r { meta: author = \"x\" events: condition: $e }"
    b = load_yaral_text(r, "r.yaral")
    d = b.detections[0]
    assert "events:no_event_variable" in d.source.unsupported
    assert observes(d, {"method": "anything"}) is None
