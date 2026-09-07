"""Rule → boxes (plan §5), including the §8.4 consistency gate.

The compiler is the one place where the region view could quietly model a *different* rule set
than the engine that actually decides whether a detection fires.  If it does, every coverage
answer built on top is about rules nobody wrote.  So the main test here does not check the
boxes against hand-written expectations: it checks them against
:func:`decnique.dsl.interpret.evaluate`, event by event, and demands they agree exactly.
"""

from __future__ import annotations

import itertools

from decnique.dsl.interpret import evaluate
from decnique.dsl.parser import parse_text
from decnique.regions.boxes import Space, categorical_axis
from decnique.regions.compile import axis_for_field, compile_rule, leaf_fields
from decnique.regions.domains import NA

METHODS = frozenset({"SetIamPolicy", "CreateServiceAccountKey", "GetIamPolicy", NA})
AGENTS = ("curl/8.0", "terraform", NA)
BYTES = (0, 10, 500, NA)


def _pred(body: str):
    return parse_text(f"detection d {{ event {body} }}", "t.decn").detections[0].spec.events[0].pred


def _space(pred, closed_method: bool = True) -> Space:
    axes = []
    for f in sorted(leaf_fields(pred) | {"method", "user_agent", "sent_bytes"}):
        if f == "method" and closed_method:
            axes.append(categorical_axis("method", METHODS))
        else:
            axes.append(axis_for_field(f))
    return Space(axes=tuple(axes))


def _events():
    """Every combination of the sampled values, including the field being absent entirely."""
    for m, a, b in itertools.product(sorted(METHODS, key=str), AGENTS, BYTES):
        point = {"method": m, "user_agent": a, "sent_bytes": b}
        event = {k: v for k, v in point.items() if v is not NA}
        yield point, event


# --- §8.4: the compiled region and the interpreter must agree, event for event ---------------

CONSISTENCY_RULES = [
    'method = "SetIamPolicy"',
    'method != "SetIamPolicy"',
    'not (method = "SetIamPolicy")',
    'method in ["SetIamPolicy", "GetIamPolicy"]',
    'method like "*IamPolicy"',
    'method matches "^Create.*Key$"',
    'method startswith "Set"',
    'method = "SetIamPolicy" and user_agent = "curl/8.0"',
    'method = "SetIamPolicy" or sent_bytes > 100',
    'not (method = "SetIamPolicy" and user_agent = "curl/8.0")',
    "sent_bytes >= 10 and sent_bytes < 500",
    "sent_bytes != 10",
    "not (sent_bytes < 10)",
    "user_agent exists",
    "not (user_agent exists)",
    'method like "*IamPolicy" and not (user_agent = "terraform")',
]


def test_compiled_boxes_agree_with_the_interpreter_on_every_event():
    """The release gate of §8.4.  A mismatch means the solver is answering about a rule set that
    is not the one the oracle enforces — the failure mode that makes every other number a lie."""
    for body in CONSISTENCY_RULES:
        pred = _pred(body)
        space = _space(pred)
        rule = compile_rule("r", pred, space)
        assert not rule.dropped, (body, rule.warnings)
        for point, event in _events():
            in_region = any(b.contains_point(point) for b in rule.boxes)
            fires = evaluate(pred, event) is True
            assert in_region == fires, (body, event, in_region, fires)


def test_a_dropped_rule_never_claims_to_cover_anything():
    """Under-approximation (§5.4): what the compiler cannot express becomes an empty region plus
    a reason, so the rule can only lose coverage it should have had — never gain coverage it
    does not have, which is the direction that hides blind spots."""
    for body, needle in [
        ('method = "SetIamPolicy" and unknown("panther:python_logic")', "unknown"),
        ('user_agent in %suspicious_agents', "reference list"),
        ('user_agent like "curl*"', "no closed value list"),
    ]:
        pred = _pred(body)
        rule = compile_rule("r", pred, _space(pred))
        assert rule.dropped is True, body
        assert rule.boxes == ()
        assert any(needle in w for w in rule.warnings), (body, rule.warnings)


def test_a_glob_on_a_closed_axis_is_expanded_exactly():
    """Plan §4.7: a glob is not a set operation, but when the axis has a known value list every
    value can simply be tried.  Without this, every rule matching `*IamPolicy` would be dropped
    and the report would be mostly caveats."""
    pred = _pred('method like "*IamPolicy"')
    rule = compile_rule("r", pred, _space(pred))
    assert not rule.dropped
    assert rule.boxes[0].get("method").values == frozenset({"SetIamPolicy", "GetIamPolicy"})
    # the same glob on an open axis has no value list to try, so the rule is dropped instead
    open_rule = compile_rule("r", pred, _space(pred, closed_method=False))
    assert open_rule.dropped is True


# --- the plan's golden cases about the missing value -----------------------------------------


def test_g4_a_rule_silent_on_an_attribute_contains_an_event_without_it():
    """G4.  Regions default to everything: a rule that never mentions `user_agent` must still
    match an event that carries none, or coverage collapses the moment a field is optional."""
    pred = _pred('method = "SetIamPolicy"')
    rule = compile_rule("r", pred, _space(pred))
    assert rule.boxes[0].contains_point({"method": "SetIamPolicy", "user_agent": NA}) is True


def test_g5_a_rule_testing_an_attribute_excludes_an_event_without_it():
    """G5, the other half: `method = POST` does not match an event with no method."""
    pred = _pred('method = "SetIamPolicy"')
    rule = compile_rule("r", pred, _space(pred))
    assert rule.boxes[0].contains_point({"method": NA}) is False


def test_negation_puts_the_missing_value_back_but_a_direct_not_equal_does_not():
    """The §5.5 null-semantics switch, in the two places it shows.  decnique's interpreter reads
    a leaf on an absent field as false, so `not (m = X)` is true there while `m != X` is not;
    getting this backwards silently moves every negated rule's region."""
    negated = compile_rule("r", _pred('not (method = "SetIamPolicy")'), _space(_pred('not (method = "SetIamPolicy")')))
    direct = compile_rule("r", _pred('method != "SetIamPolicy"'), _space(_pred('method != "SetIamPolicy"')))
    assert any(b.contains_point({"method": NA}) for b in negated.boxes) is True
    assert any(b.contains_point({"method": NA}) for b in direct.boxes) is False
    assert evaluate(_pred('not (method = "SetIamPolicy")'), {}) is True
    assert evaluate(_pred('method != "SetIamPolicy"'), {}) is False


def test_a_disjunction_becomes_several_boxes_and_a_wide_one_is_dropped():
    """DNF with the §D7 cap: a rule whose expansion explodes is dropped and flagged rather than
    silently truncated to a region that is not the rule."""
    pred = _pred('method = "SetIamPolicy" or method = "GetIamPolicy"')
    assert len(compile_rule("r", pred, _space(pred)).boxes) == 2
    wide = _pred(" or ".join(f'sent_bytes = {i}' for i in range(20)))
    assert compile_rule("r", wide, _space(wide), max_boxes=8).dropped is True
