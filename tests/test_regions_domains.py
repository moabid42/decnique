"""The per-axis set algebra (plan §4), checked exhaustively against brute-force set operations.

Every coverage answer is built out of these six operations, so an error here is not a local
bug: it silently moves the boundary of a reported hole, or drops a hole altogether.  The tests
enumerate *every* pair of values on a small universe rather than sampling, because the cases
that go wrong are the degenerate ones (empty ranges, NA-only values, touching intervals).
"""

from __future__ import annotations

import itertools

from decnique.regions.domains import NA, Categorical, Numeric, boolean

# --- brute force: the concrete point set each domain value denotes ---------------------------

NUMS = tuple(range(7))  # the numeric universe for the exhaustive tests: 0…6, plus NA
CATS = ("a", "b", "c")  # the categorical universe: three values, plus NA


def _num_points(d: Numeric) -> frozenset:
    pts = {x for x in NUMS if d.contains_point(x)}
    if d.na:
        pts.add(NA)
    return frozenset(pts)


def _num_values() -> list[Numeric]:
    out = [Numeric(lo=1, hi=0, na=na) for na in (True, False)]  # the empty range, both flags
    for lo, hi in itertools.combinations_with_replacement(NUMS, 2):
        out += [Numeric(lo=lo, hi=hi, na=na) for na in (True, False)]
    return out


def _cat_points(d: Categorical) -> frozenset:
    return frozenset(x for x in (*CATS, NA) if d.contains_point(x))


def _cat_values(universe: frozenset | None) -> list[Categorical]:
    out = []
    for n in range(len(CATS) + 2):
        for combo in itertools.combinations((*CATS, NA), n):
            out.append(Categorical(values=frozenset(combo), include=True, universe=universe))
            out.append(Categorical(values=frozenset(combo), include=False, universe=universe))
    return out


# --- numeric axis — plan §4.2 ----------------------------------------------------------------


def test_numeric_intersect_is_exactly_set_intersection():
    """A wrong intersection makes a rule cover events it does not catch, or miss ones it does —
    every 'crosses / covered' verdict downstream is read off this operation."""
    for a, b in itertools.product(_num_values(), repeat=2):
        assert _num_points(a.intersect(b)) == _num_points(a) & _num_points(b), (a, b)


def test_numeric_subtract_pieces_are_disjoint_and_cover_the_difference():
    """Subtraction is how holes are computed.  Pieces that overlap double-count a hole; pieces
    that miss part of the difference lose a real blind spot."""
    for a, b in itertools.product(_num_values(), repeat=2):
        pieces = a.subtract(b)
        seen: set = set()
        for p in pieces:
            pts = _num_points(p)
            assert not (pts & seen), (a, b, pieces)  # disjoint
            seen |= pts
        assert seen == _num_points(a) - _num_points(b), (a, b, pieces)
        assert all(not p.is_empty() for p in pieces)


def test_numeric_contains_matches_subset():
    """`contains` decides 'fully covered'.  Answering yes too eagerly reports a candidate as
    watched when part of it is not."""
    for a, b in itertools.product(_num_values(), repeat=2):
        assert a.contains(b) == (_num_points(b) <= _num_points(a)), (a, b)


def test_numeric_is_empty_matches_having_no_points():
    for a in _num_values():
        assert a.is_empty() == (not _num_points(a)), a


def test_numeric_representative_is_inside_the_value():
    """Every hole is reported with a witness event built from `representative()`.  A witness
    outside its own hole would be rejected on replay and the finding lost."""
    for a in _num_values():
        if not a.is_empty():
            assert a.contains_point(a.representative()), a


def test_discretized_bounds_leave_an_integer_hole_or_touch_exactly():
    """The plan's G1/G2/G3: measurement resolution removes boundary ambiguity, so two rules
    either tile the axis or leave a hole that is visible as whole seconds."""
    candidate = Numeric(lo=300, hi=1200, na=False)
    below, above = Numeric.at_most(599), Numeric.at_least(900)
    hole = [p for x in candidate.subtract(below) for p in x.subtract(above)]
    assert hole == [Numeric(lo=600, hi=899, na=False)]  # G1
    touching = [p for x in candidate.subtract(Numeric.at_most(599)) for p in x.subtract(Numeric.at_least(600))]
    assert touching == []  # G3: `< 600` and `>= 600` tile the axis exactly
    off_by_one = [p for x in candidate.subtract(Numeric.at_most(599)) for p in x.subtract(Numeric.at_least(601))]
    assert off_by_one == [Numeric(lo=600, hi=600, na=False)]  # G2: a one-second hole


def test_unbounded_ends_stay_unbounded():
    assert Numeric.at_least(600).subtract(Numeric.at_most(599)) == (Numeric(lo=600, hi=Numeric.top().hi, na=False),)
    assert Numeric.top().subtract(Numeric.top()) == ()


# --- categorical axis — plan §4.3 ------------------------------------------------------------


def test_categorical_algebra_on_a_closed_universe():
    """The Include/Exclude table of §4.3.  These axes carry `method`, `principal`, `role`: a
    wrong complement turns 'the rule watches everything but GET' into its opposite."""
    u = frozenset({*CATS, NA})
    for a, b in itertools.product(_cat_values(u), repeat=2):
        assert _cat_points(a.intersect(b)) == _cat_points(a) & _cat_points(b), (a, b)
        pieces = a.subtract(b)
        seen: set = set()
        for p in pieces:
            pts = _cat_points(p)
            assert not (pts & seen), (a, b)
            seen |= pts
        assert seen == _cat_points(a) - _cat_points(b), (a, b)
        assert a.contains(b) == (_cat_points(b) <= _cat_points(a)), (a, b)
        assert a.is_empty() == (not _cat_points(a)), a


def test_open_universe_containment_errs_towards_finding_holes():
    """Without a declared value list the complement cannot be enumerated, so `Include ⊇ Exclude`
    answers no.  That under-states the rule, which can only invent a hole the report labels —
    never hide one (plan §2.4)."""
    inc = Categorical.of("a", "b", NA)  # no universe: an open axis such as a user id
    exc = Categorical.but("c")
    assert inc.contains(exc) is False
    closed = frozenset({*CATS, NA})
    assert Categorical.of("a", "b", NA, universe=closed).contains(Categorical.but("c", universe=closed)) is True


def test_na_is_an_ordinary_member_so_silence_and_a_test_differ():
    """'the rule says nothing about method' includes an event with no method; 'method = POST'
    does not.  Collapsing the two is how a region wrongly swallows field-less events."""
    silent, tested = Categorical.top(), Categorical.of("POST")
    assert silent.contains_point(NA) is True
    assert tested.contains_point(NA) is False
    assert Categorical.but("POST").contains_point(NA) is True  # `method != POST` per two-valued §5.5


def test_categorical_representative_is_inside_the_value():
    for a in _cat_values(frozenset({*CATS, NA})) + _cat_values(None):
        if not a.is_empty():
            assert a.contains_point(a.representative()), a


def test_boolean_axis_is_the_categorical_algebra_over_true_false_na():
    """Plan §4.4 — `granted` is such an axis, and 'granted is not false' must keep NA."""
    assert boolean(True).contains_point(True) and not boolean(True).contains_point(NA)
    assert Categorical.but(False, universe=boolean().universe).closed() == boolean(True, NA)
