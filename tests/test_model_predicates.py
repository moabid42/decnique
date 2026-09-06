"""The predicate algebra: what every encoder and front-end builds on.

`normalize` (negation normal form) is the one with teeth.  The symbolic encoders assume NNF,
so if it ever changed what a predicate *means* the solver would answer a different question
from the oracle — and the replay step (invariant #2) would start rejecting witnesses for no
visible reason.  The property test below pins meaning against the interpreter itself, on
three-valued logic, where De Morgan is easy to get subtly wrong.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from decnique.dsl.interpret import evaluate
from decnique.model.predicates import (
    All,
    Any,
    Cmp,
    Const,
    Exists,
    In,
    InCidr,
    InList,
    Like,
    Not,
    Regex,
    StrFn,
    Unknown,
    all_of,
    any_of,
    event_vars,
    is_approximate,
    negate,
    normalize,
    referenced_fields,
    rename_var,
    unknowns,
)

M = Cmp(field=(None, "method"), op="=", value="m")
P_ = Cmp(field=(None, "principal"), op="=", value="p")
R = Cmp(field=(None, "resource"), op="=", value="r")
TRUE, FALSE = Const(value=True), Const(value=False)


# --- what a predicate mentions -----------------------------------------------------------


def test_referenced_fields_sees_through_every_node():
    p = All(
        children=(
            Not(child=Like(field=("a", "resource"), pattern="*")),
            Any(children=(Exists(field=(None, "caller_ip")), M)),
            Unknown(label="x", fields=(("b", "user_agent"),)),
        )
    )
    assert referenced_fields(p) == frozenset(
        {("a", "resource"), (None, "caller_ip"), (None, "method"), ("b", "user_agent")}
    )
    assert event_vars(p) == frozenset({"a", "b"})


def test_a_const_mentions_nothing():
    assert referenced_fields(TRUE) == frozenset() and event_vars(TRUE) == frozenset()


def test_unknowns_are_collected_from_anywhere_in_the_tree():
    u1, u2 = Unknown(label="one"), Unknown(label="two")
    p = All(children=(M, Not(child=u1), Any(children=(u2, R))))
    assert unknowns(p) == (u1, u2)
    assert is_approximate(p) is True
    assert is_approximate(All(children=(M, R))) is False


# --- building conjunctions and disjunctions ----------------------------------------------


def test_all_of_drops_true_flattens_nesting_and_short_circuits_false():
    assert all_of([]) == TRUE
    assert all_of([TRUE, TRUE]) == TRUE
    assert all_of([M]) == M
    assert all_of([M, TRUE]) == M
    assert all_of([M, FALSE, R]) == FALSE
    assert all_of([M, All(children=(P_, R))]) == All(children=(M, P_, R))


def test_any_of_is_the_mirror_image():
    assert any_of([]) == FALSE
    assert any_of([FALSE, FALSE]) == FALSE
    assert any_of([M]) == M
    assert any_of([M, FALSE]) == M
    assert any_of([M, TRUE, R]) == TRUE
    assert any_of([M, Any(children=(P_, R))]) == Any(children=(M, P_, R))


def test_negate_folds_constants_and_cancels_double_negation():
    assert negate(TRUE) == FALSE and negate(FALSE) == TRUE
    assert negate(Not(child=M)) == M
    assert negate(M) == Not(child=M)


# --- negation normal form ----------------------------------------------------------------


def test_normalize_pushes_negation_down_to_the_leaves():
    assert normalize(Not(child=All(children=(M, R)))) == Any(
        children=(Not(child=M), Not(child=R))
    )
    assert normalize(Not(child=Any(children=(M, R)))) == All(
        children=(Not(child=M), Not(child=R))
    )
    assert normalize(Not(child=Not(child=M))) == M
    assert normalize(Not(child=TRUE)) == FALSE


def test_normalize_flattens_and_deduplicates():
    assert normalize(All(children=(M, All(children=(R, M))))) == All(children=(M, R))
    assert normalize(Any(children=(M, M))) == M


def test_normalize_absorbs_constants():
    assert normalize(All(children=(M, TRUE))) == M
    assert normalize(All(children=(M, FALSE))) == FALSE
    assert normalize(Any(children=(M, FALSE))) == M
    assert normalize(Any(children=(M, TRUE))) == TRUE
    assert normalize(All(children=())) == TRUE
    assert normalize(Any(children=())) == FALSE


def test_normalize_leaves_a_negated_leaf_alone():
    """A leaf is atomic: ``not method = "m"`` must not become ``method != "m"``, because on a
    *missing* field the two do not agree."""
    assert normalize(Not(child=M)) == Not(child=M)


# --- renaming event variables ------------------------------------------------------------


def test_rename_var_rewrites_every_kind_of_reference():
    p = All(
        children=(
            Cmp(field=("a", "method"), op="=", value="m"),
            Like(field=("a", "resource"), pattern="*"),
            Regex(field=("a", "principal"), pattern="x"),
            StrFn(field=("a", "principal"), fn="contains", value="x"),
            In(field=("a", "method"), values=("x",)),
            InCidr(field=("a", "caller_ip"), cidrs=("10.0.0.0/8",)),
            InList(field=("a", "principal"), list_name="l"),
            Exists(field=("a", "caller_ip")),
            Not(child=Cmp(field=("a", "granted"), op="=", value=True)),
            Any(children=(Unknown(label="u", raw="raw", fields=(("a", "method"),)), TRUE)),
        )
    )
    renamed = rename_var(p, {"a": "b"})
    assert {v for v, _ in referenced_fields(renamed)} == {"b"}
    assert unknowns(renamed)[0].raw == "raw"  # the payload rides along untouched


def test_rename_var_only_touches_the_variables_it_was_given():
    p = All(children=(Cmp(field=("a", "method"), op="=", value="m"), M))
    assert rename_var(p, {"a": "b"}) == All(
        children=(Cmp(field=("b", "method"), op="=", value="m"), M)
    )


def test_rename_var_can_bind_the_implicit_variable():
    assert rename_var(M, {None: "e"}) == Cmp(field=("e", "method"), op="=", value="m")


# --- the property that matters -----------------------------------------------------------

_LEAVES = st.sampled_from(
    [
        Cmp(field=(None, "method"), op="=", value="m"),
        Cmp(field=(None, "granted"), op="=", value=True),
        Like(field=(None, "resource"), pattern="p/*"),
        StrFn(field=(None, "user_agent"), fn="contains", value="curl"),
        In(field=(None, "principal"), values=("u@x", "v@x")),
        Exists(field=(None, "caller_ip")),
        Unknown(label="untranslated"),
        Const(value=True),
        Const(value=False),
    ]
)

_PREDS = st.recursive(
    _LEAVES,
    lambda inner: st.one_of(
        inner.map(lambda c: Not(child=c)),
        st.lists(inner, min_size=0, max_size=3).map(lambda cs: All(children=tuple(cs))),
        st.lists(inner, min_size=0, max_size=3).map(lambda cs: Any(children=tuple(cs))),
    ),
    max_leaves=8,
)

_EVENTS = st.fixed_dictionaries(
    {},
    optional={
        "method": st.sampled_from(["m", "other"]),
        "granted": st.booleans(),
        "resource": st.sampled_from(["p/x", "q/x"]),
        "user_agent": st.sampled_from(["curl/8", "Mozilla"]),
        "principal": st.sampled_from(["u@x", "w@x"]),
        "caller_ip": st.just("10.0.0.1"),
    },
)


@given(p=_PREDS, event=_EVENTS)
def test_normalize_never_changes_what_a_predicate_means(p, event):
    assert evaluate(normalize(p), event) == evaluate(p, event), (p, event)


@given(p=_PREDS)
def test_normalize_is_idempotent(p):
    once = normalize(p)
    assert normalize(once) == once


@given(p=_PREDS)
def test_normalize_leaves_no_negation_above_a_connective(p):
    def check(q):
        if isinstance(q, Not):
            assert not isinstance(q.child, All | Any | Not | Const), q
        for child in getattr(q, "children", ()):
            check(child)
        if isinstance(q, Not):
            check(q.child)

    check(normalize(p))


@given(p=_PREDS)
def test_normalize_keeps_every_unknown(p):
    """Honesty invariant #1: normalisation must not quietly drop the atoms that make a rule
    approximate."""
    if unknowns(p):
        assert is_approximate(normalize(p)) or normalize(p) in (TRUE, FALSE)


def test_an_unknown_absorbed_by_a_constant_is_not_a_lost_unknown():
    """``unknown(...) or true`` really is true — dropping the atom there is sound, and the
    property above allows exactly that case."""
    assert normalize(Any(children=(Unknown(label="u"), TRUE))) == TRUE
    assert is_approximate(TRUE) is False
