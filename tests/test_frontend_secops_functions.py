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
