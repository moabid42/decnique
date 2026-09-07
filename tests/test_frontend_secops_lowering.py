"""SecOps (YARA-L) front-end: the correlation machinery, without the private corpus.

Single-event lowering is covered elsewhere; what only the vendored corpus ever exercised is the
rest of a real rule — ``match`` windows, joins between two event variables, ``outcome``
aggregates and the ``condition`` atoms that read them.  A mistake here changes how often a rule
is believed to fire, which is exactly what every stealth and blind-spot answer rests on.
"""

from __future__ import annotations

import pytest

from decnique.eval import fires
from decnique.frontends.secops import load_yaral_file, load_yaral_text
from decnique.model.predicates import InCidr, InList, Unknown, unknowns
from decnique.model.trace import (
    AggCall,
    AggCmp,
    CAnd,
    Count,
    CUnknown,
    Join,
)

_T = 1_700_000_000


def _rule(body: str, name: str = "r"):
    b = load_yaral_text(f"rule {name} {{\n{body}\n}}\n", f"{name}.yaral")
    assert b.detections, b.issues
    return b.detections[0]


def _two_event_rule(match: str = "  match:\n    $user over 1h\n", condition: str = "$a and $b") -> object:
    return _rule(
        '  meta:\n    author = "t"\n'
        "  events:\n"
        '    $a.metadata.event_type = "USER_LOGIN"\n'
        "    $a.principal.user.userid = $user\n"
        '    $b.metadata.event_type = "USER_UNCATEGORIZED"\n'
        "    $b.principal.user.userid = $user\n" + match + f"  condition:\n    {condition}\n"
    )


def _ev(var_type: str, at: int = _T, **kw):
    e = {"event_type": var_type, "time": at, "udm": {}}
    e.update(kw)
    return e


# --- match: grouping, window, anchor -----------------------------------------------------------


def test_a_placeholder_shared_by_two_events_becomes_a_join():
    d = _two_event_rule()
    assert d.spec.joins == (Join(("a", "principal"), ("b", "principal")),)
    assert d.spec.group_by == (("a", "principal"),)
    assert d.spec.window.seconds == 3600


def test_the_join_is_enforced_when_the_rule_is_replayed():
    """Without the join the rule would fire on two unrelated users' events."""
    d = _two_event_rule()
    same = [_ev("USER_LOGIN", principal="a@x.com"), _ev("USER_UNCATEGORIZED", _T + 60, principal="a@x.com")]
    other = [_ev("USER_LOGIN", principal="a@x.com"), _ev("USER_UNCATEGORIZED", _T + 60, principal="b@x.com")]
    assert fires(d.spec, same) is True
    assert fires(d.spec, other) is False


def test_events_outside_the_window_do_not_correlate():
    d = _two_event_rule()
    late = [_ev("USER_LOGIN", principal="a@x.com"), _ev("USER_UNCATEGORIZED", _T + 7200, principal="a@x.com")]
    assert fires(d.spec, late) is False


@pytest.mark.parametrize("side", ["before", "after"])
def test_an_anchored_window_keeps_its_anchor_and_side(side):
    d = _two_event_rule(match=f"  match:\n    $user over 30m {side} $a\n")
    assert d.spec.window.seconds == 1800
    assert d.spec.window.anchor == "a" and d.spec.window.side == side


def test_an_anchor_on_an_unknown_variable_is_reported_and_the_window_kept():
    d = _two_event_rule(match="  match:\n    $user over 30m before $zzz\n")
    assert d.spec.window.seconds == 1800 and d.spec.window.anchor is None
    assert "match:anchor:zzz" in d.source.unsupported


def test_a_match_section_with_no_window_is_reported():
    d = _two_event_rule(match="  match:\n    $user\n")
    assert "match:no_window" in d.source.unsupported


def test_an_unreadable_window_is_reported_and_not_invented():
    d = _two_event_rule(match="  match:\n    $user over 7fortnights\n")
    assert d.spec.window is None
    assert any(u.startswith("match:") for u in d.source.unsupported)


def test_grouping_by_an_event_variable_or_an_unbound_name_is_reported():
    by_var = _two_event_rule(match="  match:\n    $a over 1h\n")
    assert "match:event_variable:a" in by_var.source.unsupported
    unbound = _two_event_rule(match="  match:\n    $nothing over 1h\n")
    assert "match:unbound_placeholder:nothing" in unbound.source.unsupported


# --- ordering and cross-variable statements ----------------------------------------------------


def test_a_timestamp_comparison_orders_the_two_events():
    d = _rule(
        "  events:\n"
        '    $a.metadata.event_type = "USER_LOGIN"\n'
        '    $b.metadata.event_type = "USER_UNCATEGORIZED"\n'
        "    $a.metadata.event_timestamp.seconds < $b.metadata.event_timestamp.seconds\n"
        "  condition:\n    $a and $b\n"
    )
    assert d.spec.order == ("a", "b")
    assert fires(d.spec, [_ev("USER_LOGIN", _T), _ev("USER_UNCATEGORIZED", _T + 5)]) is True
    assert fires(d.spec, [_ev("USER_LOGIN", _T + 5), _ev("USER_UNCATEGORIZED", _T)]) is False


def test_the_reversed_timestamp_comparison_orders_them_the_other_way():
    d = _rule(
        "  events:\n"
        '    $a.metadata.event_type = "USER_LOGIN"\n'
        '    $b.metadata.event_type = "USER_UNCATEGORIZED"\n'
        "    $a.metadata.event_timestamp.seconds > $b.metadata.event_timestamp.seconds\n"
        "  condition:\n    $a and $b\n"
    )
    assert d.spec.order == ("b", "a")


def test_a_field_to_field_equality_across_two_events_is_a_join():
    d = _rule(
        "  events:\n"
        '    $a.metadata.event_type = "USER_LOGIN"\n'
        '    $b.metadata.event_type = "USER_UNCATEGORIZED"\n'
        "    $a.principal.ip = $b.principal.ip\n"
        "  condition:\n    $a and $b\n"
    )
    assert d.spec.joins == (Join(("a", "caller_ip"), ("b", "caller_ip")),)


def test_any_other_cross_variable_test_is_a_dont_know():
    """Silently dropping it would let the rule fire on pairs it never sees."""
    d = _rule(
        "  events:\n"
        '    $a.metadata.event_type = "USER_LOGIN"\n'
        '    $b.metadata.event_type = "USER_UNCATEGORIZED"\n'
        "    $a.principal.ip != $b.principal.ip\n"
        "  condition:\n    $a and $b\n"
    )
    assert any(u.startswith("events:cross_variable") for u in d.source.unsupported)
    assert unknowns(d.spec.events[0].pred)  # the test is kept as a don't-know, not dropped
    assert fires(d.spec, [_ev("USER_LOGIN"), _ev("USER_UNCATEGORIZED")]) is not True


def test_the_same_field_compared_within_one_event_is_a_dont_know():
    d = _rule(
        "  events:\n"
        '    $a.metadata.event_type = "USER_LOGIN"\n'
        "    $a.principal.ip = $a.target.ip\n"
        "  condition:\n    $a\n"
    )
    assert "secops:same_var_field_compare" in d.source.unsupported


# --- outcome aggregates and the condition that reads them ---------------------------------------


def _agg_rule(outcome: str, condition: str):
    return _rule(
        "  events:\n"
        '    $e.metadata.event_type = "USER_LOGIN"\n'
        "    $e.principal.user.userid = $user\n"
        "  match:\n    $user over 1h\n"
        f"  outcome:\n    {outcome}\n"
        f"  condition:\n    {condition}\n"
    )


def test_a_count_distinct_outcome_becomes_an_aggregate_the_condition_can_test():
    d = _agg_rule("$ips = count_distinct($e.principal.ip)", "$e and $ips > 1")
    assert d.spec.aggregates == (("ips", AggCall("count_distinct", ("e", "caller_ip"))),)
    assert d.spec.condition == CAnd((Count("e", ">=", 1), AggCmp("ips", ">", 1)))
    one_ip = [_ev("USER_LOGIN", principal="a@x.com", caller_ip="10.0.0.1")] * 2
    two_ips = [
        _ev("USER_LOGIN", principal="a@x.com", caller_ip="10.0.0.1"),
        _ev("USER_LOGIN", _T + 10, principal="a@x.com", caller_ip="10.0.0.2"),
    ]
    assert fires(d.spec, one_ip) is False
    assert fires(d.spec, two_ips) is True


@pytest.mark.parametrize("fn", ["count", "max", "min", "sum"])
def test_the_aggregate_functions_lower_to_calls_on_the_field(fn):
    d = _agg_rule(f"$n = {fn}($e.principal.ip)", "$e and $n > 0")
    assert d.spec.aggregates[0][1] == AggCall(fn, ("e", "caller_ip"))


def test_count_with_no_argument_counts_the_events():
    d = _agg_rule("$n = count()", "$e and $n > 1")
    assert d.spec.aggregates[0][1] == AggCall("count", None)


def test_an_aggregate_over_a_placeholder_uses_the_field_it_is_bound_to():
    d = _agg_rule("$n = count_distinct($user)", "$e and $n > 1")
    assert d.spec.aggregates[0][1] == AggCall("count_distinct", ("e", "principal"))


def test_arithmetic_between_aggregates_is_kept():
    d = _agg_rule("$n = count($e.principal.ip) + 1", "$e and $n > 2")
    assert d.spec.aggregates and d.spec.aggregates[0][0] == "n"


def test_a_constant_outcome_is_kept_as_a_constant():
    d = _agg_rule("$sev = max(5)", "$e and $sev > 1")
    assert d.spec.aggregates[0][1].__class__.__name__ == "AggConst"


def test_an_outcome_that_is_not_an_aggregate_is_named_in_the_condition():
    """`$risk = "high"` is not a count; testing it must not silently become "true"."""
    d = _agg_rule('$risk = "high"', "$e and $risk > 50")
    assert isinstance(d.spec.condition, CAnd)
    assert any(isinstance(c, CUnknown) for c in d.spec.condition.children)
    assert "condition:non_aggregate_outcome:risk" in d.source.unsupported


def test_counting_a_placeholder_counts_distinct_values_of_its_field():
    d = _agg_rule("$n = count()", "$e and #user > 2")
    assert any(name.startswith("__count_") for name, _ in d.spec.aggregates)


def test_a_count_of_an_unknown_name_is_a_dont_know():
    d = _agg_rule("$n = count()", "$e and #nothing > 2")
    assert "condition:unknown_count:nothing" in d.source.unsupported


def test_a_condition_naming_an_unknown_variable_is_a_dont_know():
    d = _agg_rule("$n = count()", "$e and $nothing")
    assert "condition:unknown_variable:nothing" in d.source.unsupported


def test_a_thresholded_event_count_survives():
    d = _agg_rule("$n = count()", "#e > 3")
    assert d.spec.condition == Count("e", ">", 3)
    assert fires(d.spec, [_ev("USER_LOGIN", _T + i, principal="a@x.com") for i in range(4)]) is True
    assert fires(d.spec, [_ev("USER_LOGIN", _T + i, principal="a@x.com") for i in range(3)]) is False


def test_a_negated_and_parenthesised_condition_is_kept():
    d = _agg_rule("$n = count()", "not ($e and #e > 5)")
    assert fires(d.spec, [_ev("USER_LOGIN", principal="a@x.com")]) is True


def test_a_rule_without_a_condition_requires_every_event_variable():
    d = _rule(
        "  events:\n"
        '    $a.metadata.event_type = "USER_LOGIN"\n'
        '    $b.metadata.event_type = "USER_UNCATEGORIZED"\n'
    )
    assert d.spec.condition == CAnd((Count("a", ">=", 1), Count("b", ">=", 1)))


# --- statements the parser cannot read ---------------------------------------------------------


def test_an_unparsable_event_statement_is_a_dont_know_not_a_dropped_line():
    d = _rule('  events:\n    $e.metadata.event_type = "X"\n    ??? garbage ???\n  condition:\n    $e\n')
    assert any(u.startswith("events:unparsed") for u in d.source.unsupported)
    assert fires(d.spec, [_ev("X")]) is None


def test_a_file_with_no_rule_block_is_reported():
    b = load_yaral_text("// just a comment\n", "empty.yaral")
    assert b.detections == () and any("no `rule` block" in i.message for i in b.issues)


def test_load_yaral_file_reads_from_disk(tmp_path):
    p = tmp_path / "r.yaral"
    p.write_text('rule r {\n  events:\n    $e.metadata.event_type = "X"\n  condition:\n    $e\n}\n')
    assert load_yaral_file(p).detections[0].id == "r"


def test_two_rules_in_one_file_both_load():
    text = (
        'rule one {\n  events:\n    $e.metadata.event_type = "A"\n  condition:\n    $e\n}\n'
        'rule two {\n  events:\n    $e.metadata.event_type = "B"\n  condition:\n    $e\n}\n'
    )
    assert [d.id for d in load_yaral_text(text, "two.yaral").detections] == ["one", "two"]


# --- reference lists, cidr and options -----------------------------------------------------------


def test_a_reference_list_membership_is_kept_as_a_list_test():
    d = _rule('  events:\n    $e.principal.ip in %allowed_ips\n  condition:\n    $e\n')
    leaf = d.spec.events[0].pred
    assert isinstance(leaf, InList) and leaf.list_name == "allowed_ips"


def test_a_cidr_function_becomes_a_network_test():
    d = _rule('  events:\n    net.ip_in_range_cidr($e.principal.ip, "10.0.0.0/8")\n  condition:\n    $e\n')
    assert d.spec.events[0].pred == InCidr(field=("e", "caller_ip"), cidrs=("10.0.0.0/8",))


def test_an_unknown_function_is_a_dont_know_that_names_the_fields_it_read():
    d = _rule('  events:\n    strings.concat($e.principal.ip, "x") = "y"\n  condition:\n    $e\n')
    assert any(u.startswith("secops:function:") for u in d.source.unsupported)
    assert unknowns(d.spec.events[0].pred)


def test_allow_zero_values_is_carried_into_the_rule_options():
    d = _rule('  events:\n    $e.metadata.event_type = "X"\n  condition:\n    $e\n  options:\n    allow_zero_values = true\n')
    assert d.spec.options.allow_zero_values


def test_an_unknown_option_is_kept_verbatim():
    d = _rule('  events:\n    $e.metadata.event_type = "X"\n  condition:\n    $e\n  options:\n    max_events = 5\n')
    assert ("max_events", 5) in d.spec.options.extra


def test_the_meta_block_is_kept_and_an_unverified_udm_row_is_noted():
    d = _rule(
        '  meta:\n    author = "t"\n    severity = "HIGH"\n    rule_id = "abc"\n'
        '  events:\n    $e.target.application = "iam.googleapis.com"\n'
        "  condition:\n    $e\n"
    )
    assert d.meta["author"] == "t" and d.meta["severity"] == "HIGH"
    assert d.source.native_id == "abc"
    assert any(n.startswith("udm_row_unverified:") for n in d.source.notes)


def test_a_bare_placeholder_statement_only_asks_that_the_field_exists():
    d = _rule('  events:\n    $e.metadata.event_type = "X"\n    $e.principal.ip\n  condition:\n    $e\n')
    assert fires(d.spec, [_ev("X", caller_ip="1.2.3.4")]) is True


def test_a_bare_literal_statement_is_a_dont_know():
    d = _rule('  events:\n    $e.metadata.event_type = "X"\n    "orphan"\n  condition:\n    $e\n')
    assert "secops:bare_operand" in d.source.unsupported
    assert isinstance(unknowns(d.spec.events[0].pred)[0], Unknown)
