"""SecOps front-end: placeholder assignments (``$x = $e.field``) bind exactly.

YARA-L names an intermediate value by writing the alias on the left (``$role = $e.field``),
the mirror of ``$e.field = $x``.  Both forms are pure bindings: they add no constraint, and a
later use of the placeholder (a literal, a regex, a ``%list`` membership, a cross-event join, a
``match`` group key) resolves against the bound field.  A case-folded left side
(``strings.to_lower($e.f) = $x``) binds the same way.  None of this may leave the rule
*approximate* — the value is a plain field, not a computed one.
"""

from __future__ import annotations

from decnique.frontends.secops import load_yaral_text
from decnique.model.predicates import Regex, StrFn, unknowns


def _detection(rule: str):
    return load_yaral_text(rule, "ph.yaral").detections[0]


_ALIAS = """
rule ph_alias_literal {
  events:
    $e.metadata.product_name = "Google Cloud IAM"
    $role = $e.target.resource.name
    $role = "roles/owner"
  condition:
    $e
}
"""


def test_left_side_alias_then_literal_is_exact():
    d = _detection(_ALIAS)
    assert not d.approximate, d.source.unsupported if d.source else ()
    # the literal constraint lands on the aliased field as a real Cmp, not an Unknown
    assert not unknowns(d.spec.events[0].pred)


_ALIAS_RX = """
rule ph_alias_regex {
  events:
    $e.metadata.product_name = "Google Cloud IAM"
    $u = $e.principal.user.userid
    $u = /admin/ nocase
  condition:
    $e
}
"""


def test_left_side_alias_then_regex_is_exact_regex():
    d = _detection(_ALIAS_RX)
    assert not d.approximate, d.source.unsupported if d.source else ()
    leaves = _leaves(d.spec.events[0].pred)
    assert any(isinstance(x, Regex) and x.nocase and x.pattern == "admin" for x in leaves)


_FOLDED = """
rule ph_folded_join {
  events:
    $a.metadata.product_name = "Google Cloud IAM"
    strings.to_lower($a.principal.user.userid) = $u
    $b.metadata.product_name = "Google Cloud IAM"
    $b.principal.user.userid = $u
  match:
    $u over 1h
  condition:
    $a and $b
}
"""


def test_case_folded_left_binds_and_joins():
    d = _detection(_FOLDED)
    # the placeholder is bound across two events -> a join, and it groups the match window
    assert d.spec.joins, "case-folded alias should still produce a cross-event join"
    assert d.spec.group_by, "bound placeholder should key the match window"
    assert "unbound_placeholder" not in " ".join(
        d.source.unsupported if d.source else ()
    )


def _leaves(p):
    kids = getattr(p, "children", None)
    if kids is not None:
        return [x for c in kids for x in _leaves(c)]
    child = getattr(p, "child", None)
    if child is not None:
        return _leaves(child)
    return [p]
