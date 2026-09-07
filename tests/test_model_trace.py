"""``TraceSpec`` and the four questions the encoders ask about it.

`minimal_counts` / `instantiation_size` decide **how many events the solver has to
instantiate** for a correlation rule; `is_monotone` decides whether adding more events could
ever turn a firing rule off, which is what lets the encoder stop at that size.  Get either
wrong and the coverage engine looks for a witness in a search space that cannot contain one —
it reports "no gap" for a rule it simply never tried hard enough to evade.
"""

from __future__ import annotations

import pytest

from decnique.model.predicates import Cmp, Exists
from decnique.model.trace import (
    AggBin,
    AggCall,
    AggCmp,
    AggConst,
    AggIf,
    AggRef,
    CAnd,
    CNot,
    COr,
    Count,
    CTrue,
    CUnknown,
    EventVar,
    Join,
    RuleOptions,
    TraceSpec,
    Window,
    condition_refs,
    instantiation_size,
    is_monotone,
    minimal_counts,
    referenced_fields,
    single_event,
)

A = Cmp(field=(None, "method"), op="=", value="a")
B = Cmp(field=(None, "method"), op="=", value="b")


def _spec(**kw) -> TraceSpec:
    kw.setdefault("events", (EventVar("a", A), EventVar("b", B)))
    return TraceSpec(**kw)


# --- shape -------------------------------------------------------------------------------


def test_single_event_is_the_n_equals_1_case():
    s = single_event("e", A)
    assert s.is_single_event is True
    assert s.event_names == ("e",)
    assert s.condition == Count("e", ">=", 1)


@pytest.mark.parametrize(
    "extra",
    [
        {"joins": (Join(("a", "principal"), ("b", "principal")),)},
        {"group_by": ((None, "principal"),)},
        {"window": Window(600)},
        {"aggregates": (("n", AggCall("count", None)),)},
        {"condition": Count("e", ">=", 2)},
    ],
)
def test_anything_correlated_is_not_a_single_event_rule(extra):
    base = {"events": (EventVar("e", A),), "condition": Count("e", ">=", 1)}
    assert TraceSpec(**base).is_single_event is True
    assert TraceSpec(**{**base, **extra}).is_single_event is False


def test_event_lookup_by_name():
    s = _spec()
    assert s.event("b").pred == B
    with pytest.raises(KeyError):
        s.event("nope")


def test_aggregate_map_is_keyed_by_name():
    s = _spec(aggregates=(("n", AggCall("count", None)), ("ips", AggCall("count_distinct", ("a", "caller_ip")))))
    assert set(s.aggregate_map) == {"n", "ips"}


# --- monotonicity ------------------------------------------------------------------------


def test_true_and_lower_bounded_counts_are_monotone():
    assert is_monotone(CTrue()) is True
    assert is_monotone(Count("a", ">=", 3)) is True
    assert is_monotone(Count("a", ">", 3)) is True


@pytest.mark.parametrize("op", ["=", "<", "<="])
def test_an_upper_bound_is_not_monotone(op):
    """``#a <= 2`` stops holding once a third event arrives, so the encoder may not assume
    that a bigger trace is always at least as good."""
    assert is_monotone(Count("a", op, 2)) is False


def test_negation_is_never_monotone():
    assert is_monotone(CNot(Count("a", ">=", 1))) is False


def test_and_or_are_monotone_only_when_every_part_is():
    good, bad = Count("a", ">=", 1), Count("a", "<=", 1)
    assert is_monotone(CAnd((good, good))) is True
    assert is_monotone(COr((good, good))) is True
    assert is_monotone(CAnd((good, bad))) is False
    assert is_monotone(COr((good, bad))) is False


def test_an_untranslated_condition_is_not_assumed_monotone():
    """Honesty invariant #1 in the condition: a ``CUnknown`` must not be optimised away."""
    assert is_monotone(CUnknown("panther:python")) is False


@pytest.mark.parametrize(
    ("agg", "monotone"),
    [
        (AggCall("sum", (None, "n")), True),
        (AggCall("count", None), True),
        (AggCall("count_distinct", (None, "caller_ip")), True),
        (AggCall("max", (None, "n")), True),
        (AggCall("min", (None, "n")), False),
        (AggConst(3), True),
        (AggRef("other"), False),
        (AggBin("+", AggCall("count", None), AggConst(1)), True),
        (AggBin("*", AggCall("count", None), AggCall("min", (None, "n"))), False),
        (AggBin("-", AggCall("count", None), AggConst(1)), True),
        (AggBin("-", AggCall("count", None), AggCall("count", None)), False),
        (AggIf(A, AggConst(1), AggConst(0)), False),
    ],
)
def test_which_aggregates_only_grow(agg, monotone):
    cond = AggCmp("x", ">=", 1)
    assert is_monotone(cond, {"x": agg}) is monotone


def test_an_aggregate_with_no_definition_is_not_monotone():
    assert is_monotone(AggCmp("missing", ">=", 1), {}) is False


# --- how many events the solver must instantiate -----------------------------------------


def test_every_variable_needs_at_least_one_copy():
    assert minimal_counts(_spec()) == {"a": 1, "b": 1}
    assert instantiation_size(_spec()) == 2


@pytest.mark.parametrize(("op", "n", "want"), [(">=", 3, 3), (">", 3, 4), ("=", 3, 3), ("<=", 3, 1), ("<", 3, 1)])
def test_a_count_condition_sets_the_lower_bound(op, n, want):
    s = _spec(condition=Count("a", op, n))
    assert minimal_counts(s)["a"] == want


def test_a_counting_aggregate_pushes_its_own_variable_up():
    s = _spec(
        aggregates=(("ips", AggCall("count_distinct", ("b", "caller_ip"))),),
        condition=AggCmp("ips", ">=", 4),
    )
    assert minimal_counts(s) == {"a": 1, "b": 4}


def test_a_summing_aggregate_does_not_force_more_events():
    """One event can already carry a large ``sum``, so the size stays at one."""
    s = _spec(aggregates=(("total", AggCall("sum", ("b", "n"))),), condition=AggCmp("total", ">=", 9))
    assert minimal_counts(s) == {"a": 1, "b": 1}


def test_bounds_are_collected_through_and_or_and_not():
    s = _spec(condition=CAnd((Count("a", ">=", 2), COr((Count("b", ">", 2), CNot(Count("a", ">=", 5)))))))
    assert minimal_counts(s) == {"a": 5, "b": 3}
    assert instantiation_size(s) == 8


# --- which fields a variable touches ------------------------------------------------------


def test_referenced_fields_gathers_from_predicate_join_group_and_aggregate():
    s = _spec(
        events=(EventVar("a", Cmp(field=(None, "method"), op="=", value="a")), EventVar("b", B)),
        joins=(Join(("a", "principal"), ("b", "principal")),),
        group_by=(("a", "resource"), ("b", "service")),
        aggregates=(
            ("ips", AggCall("count_distinct", ("a", "caller_ip"))),
            ("cond", AggIf(Exists(field=("a", "user_agent")), AggConst(1), AggRef("ips"))),
        ),
    )
    assert referenced_fields(s, "a") == frozenset(
        {"method", "principal", "resource", "caller_ip", "user_agent"}
    )
    assert referenced_fields(s, "b") == frozenset({"method", "service", "principal"})


def test_an_unqualified_field_belongs_to_whichever_variable_is_asked():
    s = _spec(group_by=((None, "resource"),))
    assert "resource" in referenced_fields(s, "a")
    assert "resource" in referenced_fields(s, "b")


def test_condition_refs_reports_the_variables_and_aggregates_compared():
    c = CAnd((Count("a", ">=", 1), COr((AggCmp("ips", ">", 1), CNot(Count("b", ">=", 1))))))
    assert condition_refs(c) == ({"a", "b"}, {"ips"})
    assert condition_refs(CTrue()) == (set(), set())


# --- options -----------------------------------------------------------------------------


def test_rule_options_default_to_the_strict_reading():
    assert RuleOptions().allow_zero_values is False
    assert RuleOptions().extra == ()
