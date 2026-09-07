"""The two ways to compute a hole, and the rule for choosing one — plan §7.3–§7.5.

Both answer the same question — ``candidate \\ ⋃rules``, as a list of boxes — and on a box-type
candidate they must agree; :mod:`tests.test_regions_backends` checks that point by point,
because a disagreement is a bug in one of them and there is no third opinion to break the tie.

* **interval** — pure box subtraction (:func:`decnique.regions.boxes.subtract_all`).  Exact,
  deterministic, and the pieces it returns are disjoint, so nothing is double-counted.  Its
  weakness is fragmentation: each rule can split every hole again, and a candidate with many
  axes and many overlapping rules can outrun the cap.
* **smt** — z3 over the same axes: ``candidate ∧ ¬⋁rules``, one model at a time, each model
  grown into a box that is *verified* to lie wholly inside the hole before it is reported, then
  blocked so the search moves on.  It does not fragment, and it answers "covered" as an UNSAT
  proof, but its boxes are greedy rather than canonical and it is the slower of the two.

``auto`` runs the interval backend and hands over to SMT only when the cap is hit, which is the
plan's rule and keeps the fast, exact path in charge of the ordinary case.
"""

from __future__ import annotations

from dataclasses import dataclass

import z3

from decnique.regions.boxes import Box, Difference, Space, subtract_all
from decnique.regions.domains import NA, Categorical, Domain, Numeric, Point

BACKENDS = ("auto", "interval", "smt")
DEFAULT_MAX_BOXES = 64  # SMT: how many holes to enumerate before saying "there are more"


def solve(
    candidate: Box,
    rules: tuple[Box, ...],
    *,
    backend: str = "auto",
    max_holes: int | None = None,
) -> Difference:
    """``candidate \\ ⋃rules`` by the chosen backend (plan §7.5)."""
    if backend not in BACKENDS:
        raise ValueError(f"backend must be one of {', '.join(BACKENDS)}")
    if backend == "smt":
        return smt_difference(candidate, rules, max_holes=max_holes or DEFAULT_MAX_BOXES)
    kw = {} if max_holes is None else {"max_holes": max_holes}
    got = subtract_all(candidate, rules, **kw)  # type: ignore[arg-type]
    if got.overflowed and backend == "auto":
        return smt_difference(candidate, rules, max_holes=DEFAULT_MAX_BOXES)
    return got


# --- the SMT backend — plan §7.4 --------------------------------------------------------------


@dataclass(slots=True)
class _Vars:
    """One z3 term plus a presence bit per axis.  ``NA`` is the absence of the presence bit, so
    it can never collide with a real value that happens to spell the same thing."""

    space: Space
    term: dict[str, z3.ExprRef]
    present: dict[str, z3.BoolRef]
    covered: z3.BoolRef | None = None  # ⋁rules, kept for the optimisation queries of §7.4

    @staticmethod
    def of(space: Space) -> _Vars:
        term: dict[str, z3.ExprRef] = {}
        present: dict[str, z3.BoolRef] = {}
        for axis in space.axes:
            name = axis.name
            present[name] = z3.Bool(f"{name}?")
            if isinstance(axis.top, Numeric):
                term[name] = z3.Int(name)
            elif _is_bool_axis(axis.top):
                term[name] = z3.Bool(name)
            else:
                term[name] = z3.String(name)
        return _Vars(space=space, term=term, present=present)

    def box(self, box: Box) -> z3.BoolRef:
        parts = [
            box.get(n).to_smt(self.term[n], self.present[n])
            for n in self.space.names()
        ]
        return z3.And(*parts) if parts else z3.BoolVal(True)

    def point(self, model: z3.ModelRef) -> dict[str, Point]:
        out: dict[str, Point] = {}
        for name in self.space.names():
            if not z3.is_true(model.eval(self.present[name], model_completion=True)):
                out[name] = NA
                continue
            v = model.eval(self.term[name], model_completion=True)
            if z3.is_bool(self.term[name]):
                out[name] = z3.is_true(v)
            elif z3.is_int(self.term[name]):
                out[name] = v.as_long()
            else:
                out[name] = v.as_string()
        return out


def _is_bool_axis(top: object) -> bool:
    return (
        isinstance(top, Categorical)
        and top.universe is not None
        and all(isinstance(v, bool) for v in top.universe if v is not NA)
        and bool(top.universe - {NA})
    )


def smt_difference(
    candidate: Box, rules: tuple[Box, ...], *, max_holes: int = DEFAULT_MAX_BOXES
) -> Difference:
    space = candidate.space
    v = _Vars.of(space)
    v.covered = z3.Or(*[v.box(r) for r in rules]) if rules else z3.BoolVal(False)
    covered = v.covered

    search = z3.Solver()
    search.set("random_seed", 0)  # reproducible holes, like every other number in this tool
    search.add(v.box(candidate), z3.Not(covered))

    # the opposite question, asked of a candidate box: does any point of it meet a rule?
    # UNSAT means the whole box is a hole, which is what makes a grown box safe to report.
    check = z3.Solver()
    check.set("random_seed", 0)
    check.add(v.box(candidate), covered)

    holes: list[Box] = []
    for _ in range(max_holes):
        if search.check() != z3.sat:
            return Difference(holes=tuple(holes))
        point = v.point(search.model())
        box = _grow(point, candidate, check, v)
        holes.append(box)
        search.add(z3.Not(v.box(box)))
    return Difference(holes=tuple(holes), overflowed=True)


def _grow(point: dict[str, Point], candidate: Box, check: z3.Solver, v: _Vars) -> Box:
    """Widen one evading point into a box, axis by axis, keeping only what is *proven* to lie
    wholly inside the hole.

    A numeric axis is widened by asking where the nearest covered value is on each side — two
    optimisation queries, which give the exact maximal interval around the point rather than a
    guess.  A categorical axis is widened to the candidate's whole value set when that is still
    a hole, and otherwise, if the axis has a declared value list, by dropping the values that
    are covered.  Axes are handled in a fixed order, so the same input always gives the same box.
    """
    space = candidate.space
    cons: dict[str, Domain] = {n: _pin(space.axis(n), point.get(n, NA)) for n in space.names()}
    for name in space.names():
        axis, wide = space.axis(name), candidate.get(name)
        if _is_hole(Box.of(space, {**cons, name: wide}), check, v):
            cons[name] = wide  # the whole axis is a hole here; nothing finer to compute
            continue
        pt = point.get(name, NA)
        if isinstance(axis.top, Numeric) and pt is not NA:
            grown = _grow_interval(name, int(pt), cons, candidate, v)  # type: ignore[arg-type]
        elif isinstance(wide, Categorical) and wide.universe is not None:
            grown = _grow_values(name, wide, cons, space, check, v)
        else:
            continue
        trial = Box.of(space, {**cons, name: grown})
        if _is_hole(trial, check, v):
            cons[name] = grown
    return Box.of(space, cons)


def _grow_interval(
    name: str, at: int, cons: dict[str, Domain], candidate: Box, v: _Vars
) -> Numeric:
    """The largest interval around ``at`` on one axis that no rule reaches into, found by
    minimising the covered values above it and maximising those below it (plan §7.4, query 2)."""
    term = v.term[name]
    fixed = [v.box(candidate)] + [
        cons[n].to_smt(v.term[n], v.present[n]) for n in cons if n != name
    ]
    covered = v.covered
    assert covered is not None
    hi = _edge(term, fixed, covered, above=True, at=at)
    lo = _edge(term, fixed, covered, above=False, at=at)
    wide = candidate.get(name)
    assert isinstance(wide, Numeric)
    return Numeric(
        lo=wide.lo if lo is None else lo,
        hi=wide.hi if hi is None else hi,
        na=False,
    ).intersect(wide)


def _edge(
    term: z3.ExprRef, fixed: list[z3.BoolRef], covered: z3.BoolRef, *, above: bool, at: int
) -> int | None:
    """The first covered value strictly above (or below) ``at``, moved one step inwards.
    ``None`` means the rules never reach that side, so the candidate's own bound stands."""
    opt = z3.Optimize()
    opt.set("random_seed", 0)
    opt.add(*fixed, covered, term > z3.IntVal(at) if above else term < z3.IntVal(at))
    handle = opt.minimize(term) if above else opt.maximize(term)
    if opt.check() != z3.sat:
        return None
    value = opt.model().eval(term, model_completion=True).as_long()
    del handle
    return value - 1 if above else value + 1


def _grow_values(
    name: str, wide: Categorical, cons: dict[str, Domain], space: Space, check: z3.Solver, v: _Vars
) -> Categorical:
    """A closed axis: keep every value of the candidate's set that is a hole on its own."""
    keep = [
        value
        for value in wide.closed().values
        if _is_hole(
            Box.of(space, {**cons, name: Categorical(values=frozenset({value}), include=True,
                                                     universe=wide.universe)}),
            check,
            v,
        )
    ]
    return Categorical(values=frozenset(keep), include=True, universe=wide.universe)


def _is_hole(box: Box, check: z3.Solver, v: _Vars) -> bool:
    """Is every point of ``box`` outside every rule?  One UNSAT query — the reason a grown box
    can be reported as a hole rather than merely believed to be one."""
    check.push()
    try:
        check.add(v.box(box))
        return check.check() == z3.unsat
    finally:
        check.pop()


def _pin(axis, value: Point) -> Domain:  # type: ignore[no-untyped-def]
    """The one-point region on an axis."""
    if isinstance(axis.top, Numeric):
        return Numeric.only_na() if value is NA else Numeric.exactly(int(value))  # type: ignore[arg-type]
    universe = axis.top.universe if isinstance(axis.top, Categorical) else None
    return Categorical(values=frozenset({value}), include=True, universe=universe)
