"""The two backends must give the same answer — plan §7.5 and §10.3.

The interval backend and the SMT backend compute ``candidate \\ ⋃rules`` by completely
different means, so agreement is real evidence and disagreement is a bug in one of them with no
third opinion to break the tie.  They are compared by the *points* their holes contain, not by
the boxes themselves: the two are allowed to carve the same region into different pieces, and
only the region is the answer.
"""

from __future__ import annotations

import random

from decnique.regions.backends import solve
from decnique.regions.boxes import Box, Space, categorical_axis, numeric_axis
from decnique.regions.domains import NA, Categorical, Numeric

WINDOW = tuple(range(6))
METHOD = ("get", "set", "list")
CLOSED = frozenset({*METHOD, NA})
SPACE = Space(axes=(numeric_axis("span", "s"), categorical_axis("method", CLOSED)))
POINTS = [{"span": w, "method": m} for w in (*WINDOW, NA) for m in (*METHOD, NA)]


def _points(boxes) -> frozenset:
    out = set()
    for b in boxes:
        out |= {tuple(sorted(p.items(), key=str)) for p in POINTS if b.contains_point(p)}
    return frozenset(out)


def _rule(rng: random.Random) -> Box:
    cons = {}
    if rng.random() < 0.8:
        lo, hi = sorted(rng.sample(WINDOW, 2))
        cons["span"] = Numeric(lo=lo, hi=hi, na=rng.random() < 0.3)
    if rng.random() < 0.7:
        vals = frozenset(rng.sample([*METHOD, NA], rng.randint(1, 3)))
        cons["method"] = Categorical(values=vals, include=rng.random() < 0.7)
    return SPACE.box(cons)


def _candidate(rng: random.Random) -> Box:
    lo, hi = sorted(rng.sample(WINDOW, 2))
    cons = {"span": Numeric(lo=lo, hi=hi, na=rng.random() < 0.3)}
    if rng.random() < 0.6:
        cons["method"] = Categorical(
            values=frozenset(rng.sample([*METHOD, NA], rng.randint(1, 3))), include=True
        )
    return SPACE.box(cons)


def test_the_two_backends_report_the_same_region():
    """The plan makes this a release gate: whichever backend the user selects, the reported
    blind spot must be the same set of events."""
    rng = random.Random(0)
    for _ in range(40):
        cand = _candidate(rng)
        rules = tuple(_rule(rng) for _ in range(rng.randint(0, 3)))
        a = solve(cand, rules, backend="interval")
        b = solve(cand, rules, backend="smt")
        assert not a.overflowed and not b.overflowed
        assert _points(a.holes) == _points(b.holes), (
            cand.text(), [r.text() for r in rules],
            [h.text() for h in a.holes], [h.text() for h in b.holes],
        )
        assert a.covered == b.covered


def test_both_backends_prove_full_coverage_the_same_way():
    """'covered' is the strong claim in this tool — it says an attacker has nowhere to stand.
    Both backends must reach it only when it is true."""
    cand = SPACE.box({"span": Numeric(lo=0, hi=5, na=False)})
    rules = (SPACE.box({"span": Numeric.at_most(2)}), SPACE.box({"span": Numeric.at_least(3)}))
    for backend in ("interval", "smt"):
        assert solve(cand, rules, backend=backend).covered is True
    assert solve(cand, rules[:1], backend="interval").covered is False
    assert solve(cand, rules[:1], backend="smt").covered is False


def test_every_hole_point_is_really_uncovered():
    """Soundness, checked directly rather than through the other backend: a witness taken from
    a reported hole must fall outside every rule."""
    rng = random.Random(1)
    for _ in range(25):
        cand = _candidate(rng)
        rules = tuple(_rule(rng) for _ in range(rng.randint(1, 3)))
        for backend in ("interval", "smt"):
            for hole in solve(cand, rules, backend=backend).holes:
                w = hole.witness()
                assert cand.contains_point(w), (backend, hole.text())
                assert not any(r.contains_point(w) for r in rules), (backend, w)


def test_auto_hands_over_to_smt_when_the_interval_backend_fragments():
    """Fragmentation is the interval backend's one weakness: alternating rules split a hole on
    every pass.  `auto` must notice and switch, not report a truncated list as the whole truth."""
    cand = SPACE.box({"span": Numeric(lo=0, hi=5, na=False)})
    rules = tuple(SPACE.box({"span": Numeric.exactly(w)}) for w in (1, 3))
    assert solve(cand, rules, backend="interval", max_holes=1).overflowed is True
    auto = solve(cand, rules, backend="auto", max_holes=1)
    assert auto.overflowed is False
    assert _points(auto.holes) == _points(solve(cand, rules, backend="interval").holes)


def test_an_unknown_backend_name_is_refused():
    try:
        solve(SPACE.top(), (), backend="magic")
    except ValueError as e:
        assert "auto" in str(e)
    else:
        raise AssertionError("an unknown backend name must not fall back silently")


def test_the_roadmap_example_comes_out_as_a_range_and_a_value():
    """The shape the whole feature exists for: not one example event, but 'every run whose span
    lands between these two numbers, on this method, is seen by nobody'."""
    cand = SPACE.box({"span": Numeric(lo=300, hi=1200, na=False)})
    rules = (
        SPACE.box({"span": Numeric.at_most(599)}),
        SPACE.box({"span": Numeric.at_least(900)}),
        SPACE.box({"method": Categorical.of("get")}),
    )
    for backend in ("interval", "smt"):
        holes = solve(cand, rules, backend=backend).holes
        assert len(holes) == 1
        assert holes[0].get("span") == Numeric(lo=600, hi=899, na=False)
        assert holes[0].get("method").closed() == Categorical.of("set", "list", NA, universe=CLOSED)
