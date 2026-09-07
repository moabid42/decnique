"""Boxes and the hole computation (plan §4.8, §7.1, §7.3), checked against brute force.

This is the machinery that turns "one example event" into "the whole evading set".  If it is
wrong, the tool reports a region that is not really a blind spot (a false alarm the analyst
chases) or, worse, quietly drops part of a real one.  Every test below therefore compares the
box answer with the same answer computed by listing points one at a time on a tiny space.
"""

from __future__ import annotations

import itertools
import random

from decnique.regions.boxes import (
    COVERED,
    DISJOINT,
    INSIDE,
    PARTIAL,
    Box,
    Space,
    box_subtract,
    categorical_axis,
    classify,
    numeric_axis,
    subtract_all,
)
from decnique.regions.domains import NA, Categorical, Numeric

WINDOW = tuple(range(5))
METHOD = ("a", "b")
SPACE = Space(axes=(numeric_axis("window", "s"), categorical_axis("method")))
POINTS = [
    {"window": w, "method": m}
    for w in (*WINDOW, NA)
    for m in (*METHOD, NA)
]


def _points(box: Box) -> frozenset:
    return frozenset(tuple(sorted(p.items(), key=str)) for p in POINTS if box.contains_point(p))


CLOSED = frozenset({*METHOD, NA})
# The same two axes, once with `method` left open (its value list is not knowable — real method
# names are) and once declared closed.  Brute force can only be compared against the closed one,
# because on an open axis "any other value" is a real region a finite point listing cannot see.
CLOSED_SPACE = Space(axes=(numeric_axis("window", "s"), categorical_axis("method", CLOSED)))


def _cat(rng: random.Random) -> Categorical:
    vals = frozenset(rng.sample([*METHOD, NA], rng.randint(0, 3)))
    return Categorical(values=vals, include=rng.random() < 0.5)


def _boxes(rng: random.Random, n: int, space: Space = SPACE) -> list[Box]:
    """Rule boxes: anything, including bounds outside the sampled window."""
    out = []
    for _ in range(n):
        lo, hi = sorted(rng.sample(range(-1, 6), 2))
        keep = rng.random()
        cons = {}
        if keep < 0.8:
            cons["window"] = Numeric(lo=lo, hi=hi, na=rng.random() < 0.5)
        if keep > 0.2:
            cons["method"] = _cat(rng)
        out.append(space.box(cons))
    return out


def _candidates(rng: random.Random, n: int, space: Space = SPACE) -> list[Box]:
    """Candidate boxes, always bounded inside the sampled universe — a real technique runs a
    fixed number of steps over a bounded span, so its reachable set is never unbounded, and
    only then can a box answer be compared with a finite point listing."""
    out = []
    for _ in range(n):
        lo, hi = sorted(rng.sample(WINDOW, 2))
        cons = {"window": Numeric(lo=lo, hi=hi, na=rng.random() < 0.5)}
        if rng.random() < 0.8:
            cons["method"] = _cat(rng)
        out.append(space.box(cons))
    return out


# --- the difference ---------------------------------------------------------------------------


def test_box_subtract_pieces_are_disjoint_and_exact():
    """`box_subtract` is applied once per rule per hole.  Overlapping pieces would report the
    same blind spot twice; missing points would lose part of it."""
    rng = random.Random(0)  # plan §4: reproducible, like every other number in this tool
    for h, p in itertools.product(_candidates(rng, 30, CLOSED_SPACE), _boxes(rng, 30, CLOSED_SPACE)):
        pieces = box_subtract(h, p)
        seen: set = set()
        for piece in pieces:
            pts = _points(piece)
            assert not (pts & seen), (h.text(), p.text())
            seen |= pts
        assert seen == _points(h) - _points(p), (h.text(), p.text())


def test_subtract_all_is_the_set_difference_against_every_rule():
    """The headline claim: the reported holes are exactly the candidate minus the union of the
    rules.  Anything else makes the coverage answer wrong in one direction or the other."""
    rng = random.Random(0)
    for cand in _candidates(rng, 12, CLOSED_SPACE):
        rules = tuple(_boxes(rng, 4, CLOSED_SPACE))
        d = subtract_all(cand, rules)
        got: set = set()
        for h in d.holes:
            pts = _points(h)
            assert not (pts & got)  # disjoint
            got |= pts
        union: set = set()
        for r in rules:
            union |= _points(r)
        assert got == _points(cand) - union, (cand.text(), [r.text() for r in rules])
        assert d.covered == (not (_points(cand) - union))


def test_every_hole_carries_a_witness_inside_it_and_outside_every_rule():
    """A region nobody can turn into a concrete event is not usable evidence; the witness is
    what gets replayed through the oracle before the finding is believed."""
    rng = random.Random(1)
    for cand in _candidates(rng, 12, CLOSED_SPACE):
        rules = tuple(_boxes(rng, 3, CLOSED_SPACE))
        for h in subtract_all(cand, rules).holes:
            w = h.witness()
            assert h.contains_point(w), (h.text(), w)
            assert cand.contains_point(w)
            assert not any(r.contains_point(w) for r in rules), (w, [r.text() for r in rules])


def test_a_rule_that_swallows_the_candidate_leaves_nothing():
    cand = SPACE.box({"window": Numeric(lo=1, hi=3, na=False), "method": Categorical.of("a")})
    assert subtract_all(cand, (SPACE.top(),)).covered is True
    assert subtract_all(cand, ()).holes == (cand,)


def test_the_hole_cap_reports_overflow_instead_of_a_wrong_answer():
    """On overflow the interval backend must say so — the SMT backend then takes over.  Silently
    truncating the list would report 'fewer holes' as if that were the truth (plan §7.3 / D8)."""
    cand = SPACE.box({"window": Numeric(lo=0, hi=4, na=False)})
    rules = tuple(SPACE.box({"window": Numeric.exactly(w)}) for w in (1, 3))  # fragments [0,4]
    d = subtract_all(cand, rules, max_holes=1)
    assert d.overflowed is True
    assert d.covered is False  # an overflowed result is never reported as covered


# --- pairwise classification — plan §7.1 -----------------------------------------------------


def test_classification_matches_the_set_relations():
    """The per-rule table in the report reads off these four verdicts."""
    rng = random.Random(2)
    for c, r in itertools.product(_candidates(rng, 20, CLOSED_SPACE), _candidates(rng, 20, CLOSED_SPACE)):
        cp, rp = _points(c), _points(r)
        got = classify(c, r)
        if not (cp & rp):
            assert got == DISJOINT
        elif cp <= rp:
            assert got == COVERED
        elif rp <= cp:
            assert got == INSIDE
        else:
            assert got == PARTIAL


def test_an_open_axis_never_reports_covered_when_it_is_not():
    """With no declared value list the algebra may fall back from `covered` to `partial`; what it
    must never do is claim a candidate is watched when part of it is not."""
    rng = random.Random(3)
    for c, r in itertools.product(_candidates(rng, 20), _boxes(rng, 20)):
        cp, rp = _points(c), _points(r)
        got = classify(c, r)
        if got == COVERED:
            assert cp <= rp, (c.text(), r.text())
        if got == DISJOINT:
            assert not (cp & rp), (c.text(), r.text())


def test_escape_axes_name_where_the_candidate_reaches_past_the_rule():
    """The escape set tells the analyst *which knob* the attacker turns to leave the rule."""
    cand = SPACE.box({"window": Numeric(lo=0, hi=1000, na=False), "method": Categorical.of("a")})
    rule = SPACE.box({"window": Numeric.at_most(599), "method": Categorical.of("a")})
    assert cand.escape_axes(rule) == ("window",)
    assert cand.escape_axes(SPACE.top()) == ()


def test_on_an_open_axis_every_other_value_is_a_real_hole():
    """`method` has no closed value list: rules naming `a` and `b` leave every *other* method
    uncovered, and that is the honest answer — it is how a method nobody wrote a rule for shows
    up as unwatched instead of vanishing because it was never enumerated."""
    cand = SPACE.top()
    rules = (SPACE.box({"method": Categorical.of("a")}), SPACE.box({"method": Categorical.of("b")}))
    holes = subtract_all(cand, rules).holes
    assert len(holes) == 1
    assert holes[0].get("method") == Categorical.but("a", "b")
    assert holes[0].contains_point({"method": "c", "window": NA})
    # declare the list closed and the same question answers "covered but for the missing value"
    shut = subtract_all(CLOSED_SPACE.top(), tuple(
        CLOSED_SPACE.box({"method": Categorical.of(m)}) for m in METHOD))
    assert [h.get("method").closed() for h in shut.holes] == [
        Categorical.of(NA, universe=CLOSED)
    ]  # only "the event carried no method at all" is left


def test_an_unmentioned_axis_is_the_whole_axis_including_missing():
    """Regions default to everything, points default to NA.  A rule silent about `method` must
    still cover an event that carries no method at all."""
    silent = SPACE.box({"window": Numeric.at_most(10)})
    assert silent.contains_point({"window": 5, "method": NA}) is True
    assert silent.get("method").contains_point(NA) is True
