"""Per-axis set algebra — the coverage-gap plan §4.

Coverage needs *set* operations and nothing else: no distances, no numeric embedding of a
categorical axis.  Every axis type implements the same six operations, so the box machinery in
:mod:`decnique.regions.boxes` and both backends never need to know an axis's type:

    ``TOP``  ``intersect``  ``subtract``  ``contains``  ``is_empty``  ``contains_point``
    ``representative``  ``to_smt``

Two rules hold everywhere and are the source of most of the care in this file:

* **Regions default to "everything", points default to ``NA``.**  Never the other way round.
  A rule that is silent about ``method`` accepts every method *including an event that carries
  no method at all*; an event that does not carry ``method`` has the value ``NA``.
* **``NA`` is part of every domain.**  It is an ordinary member of the value universe, so
  ``method = "POST"`` (which excludes ``NA``) and "no test on method" (which includes it) stay
  distinguishable.  In SMT it is the absence of the axis's presence bit, so ``NA`` can never
  collide with a real string that happens to spell it.

Unbounded numeric ends use ``math.inf``, which compares and adds like the sentinel the plan
asks for (``inf + 1`` is still ``inf``, so an empty piece stays empty).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace
from typing import Protocol, runtime_checkable

import z3

INF = math.inf
Bound = int | float
Point = str | int | bool | None  # None is NA — the value of an axis the event does not carry
NA: Point = None


@runtime_checkable
class Domain(Protocol):
    """The algebra every axis type implements (plan §4.1)."""

    def intersect(self, other: Domain) -> Domain: ...
    def subtract(self, other: Domain) -> tuple[Domain, ...]: ...
    def contains(self, other: Domain) -> bool: ...
    def is_empty(self) -> bool: ...
    def contains_point(self, x: Point) -> bool: ...
    def representative(self) -> Point: ...
    def to_smt(self, term: z3.ExprRef, present: z3.BoolRef) -> z3.BoolRef: ...
    def text(self) -> str: ...


# --- numeric axes (durations, counts, rates) — plan §4.2 -------------------------------------


@dataclass(frozen=True, slots=True)
class Numeric:
    """A closed integer interval plus a flag for ``NA``.

    Values are already at the axis's measurement resolution (seconds, whole counts), so
    ``window < 600`` is ``[0, 599]`` and ``window >= 600`` is ``[600, INF]``: two rules either
    touch exactly or leave an integer-sized hole, and both cases are detectable.  Open/closed
    boundary ambiguity does not exist here — there are no boundaries to get wrong.
    """

    lo: Bound = -INF
    hi: Bound = INF
    na: bool = True

    @staticmethod
    def top() -> Numeric:
        return Numeric()

    @staticmethod
    def empty() -> Numeric:
        return Numeric(lo=1, hi=0, na=False)

    @staticmethod
    def only_na() -> Numeric:
        return Numeric(lo=1, hi=0, na=True)

    @staticmethod
    def at_least(n: Bound, *, na: bool = False) -> Numeric:
        return Numeric(lo=n, hi=INF, na=na)

    @staticmethod
    def at_most(n: Bound, *, na: bool = False) -> Numeric:
        return Numeric(lo=-INF, hi=n, na=na)

    @staticmethod
    def exactly(n: Bound, *, na: bool = False) -> Numeric:
        return Numeric(lo=n, hi=n, na=na)

    @property
    def empty_range(self) -> bool:
        # ±INF is a sentinel for "no bound", never a member: subtracting an unbounded side
        # would otherwise leave a degenerate [-INF, -INF] piece that holds no integer at all
        return self.lo > self.hi or (self.lo == self.hi and self.lo in (INF, -INF))

    def is_empty(self) -> bool:
        return self.empty_range and not self.na

    def intersect(self, other: Domain) -> Numeric:
        o = _as(other, Numeric)
        return Numeric(lo=max(self.lo, o.lo), hi=min(self.hi, o.hi), na=self.na and o.na)

    def subtract(self, other: Domain) -> tuple[Numeric, ...]:
        """``self \\ other`` as disjoint pieces: what is below the hole, what is above it, and
        ``NA`` on its own when this side carries it and the other does not."""
        o = _as(other, Numeric)
        out: list[Numeric] = []
        if self.na and not o.na:
            out.append(Numeric(lo=1, hi=0, na=True))
        if self.empty_range:
            return tuple(p for p in out if not p.is_empty())
        if o.empty_range:  # nothing removed from the range
            out.append(replace(self, na=False))
            return tuple(p for p in out if not p.is_empty())
        below = Numeric(lo=self.lo, hi=min(self.hi, _pred(o.lo)), na=False)
        above = Numeric(lo=max(self.lo, _succ(o.hi)), hi=self.hi, na=False)
        out.extend([below, above])
        return tuple(p for p in out if not p.is_empty())

    def contains(self, other: Domain) -> bool:
        o = _as(other, Numeric)
        if o.is_empty():
            return True
        if o.na and not self.na:
            return False
        if o.empty_range:
            return True
        return self.lo <= o.lo and o.hi <= self.hi

    def contains_point(self, x: Point) -> bool:
        if x is NA:
            return self.na
        if isinstance(x, bool) or not isinstance(x, int | float):
            return False
        return self.lo <= x <= self.hi

    def representative(self) -> Point:
        if self.empty_range:
            return NA  # an empty range holds nothing but NA (and nothing at all when na is off)
        if self.lo != -INF:
            return int(self.lo)
        if self.hi != INF:
            return int(self.hi)
        return 0

    def to_smt(self, term: z3.ExprRef, present: z3.BoolRef) -> z3.BoolRef:
        parts: list[z3.BoolRef] = []
        if not self.empty_range:
            rng = [present]
            if self.lo != -INF:
                rng.append(term >= z3.IntVal(int(self.lo)))
            if self.hi != INF:
                rng.append(term <= z3.IntVal(int(self.hi)))
            parts.append(z3.And(*rng))
        if self.na:
            parts.append(z3.Not(present))
        return z3.Or(*parts) if parts else z3.BoolVal(False)

    def text(self) -> str:
        if self.is_empty():
            return "nothing"
        body = ""
        if not self.empty_range:
            if self.lo == -INF and self.hi == INF:
                body = "any"
            elif self.lo == -INF:
                body = f"≤ {_num(self.hi)}"
            elif self.hi == INF:
                body = f"≥ {_num(self.lo)}"
            elif self.lo == self.hi:
                body = f"= {_num(self.lo)}"
            else:
                body = f"∈ [{_num(self.lo)}, {_num(self.hi)}]"
        if self.na:
            return f"{body} or missing" if body else "missing"
        return body


def _succ(x: Bound) -> Bound:
    return x + 1 if x != INF and x != -INF else x


def _pred(x: Bound) -> Bound:
    return x - 1 if x != INF and x != -INF else x


def _num(x: Bound) -> str:
    return str(int(x)) if x not in (INF, -INF) else ("∞" if x == INF else "-∞")


# --- categorical axes (method, principal, resource, …) — plan §4.3 ---------------------------


@dataclass(frozen=True, slots=True)
class Categorical:
    """``Include(S)`` or ``Exclude(S)`` over a value universe that contains ``NA``.

    ``universe`` is the axis's closed value list when the schema declares one (booleans, a
    small enum).  With it, ``Exclude`` can be turned back into ``Include`` and containment is
    exact in both directions.  Without it — user ids, resource names, anything open — a query
    that would need to enumerate the complement answers *no*, which under-approximates the
    rule and so can only invent a hole, never hide one (plan §2.4).
    """

    values: frozenset[Point]
    include: bool = True
    universe: frozenset[Point] | None = None

    @staticmethod
    def top(universe: frozenset[Point] | None = None) -> Categorical:
        return Categorical(values=frozenset(), include=False, universe=universe)

    @staticmethod
    def empty(universe: frozenset[Point] | None = None) -> Categorical:
        return Categorical(values=frozenset(), include=True, universe=universe)

    @staticmethod
    def of(*values: Point, universe: frozenset[Point] | None = None) -> Categorical:
        return Categorical(values=frozenset(values), include=True, universe=universe)

    @staticmethod
    def but(*values: Point, universe: frozenset[Point] | None = None) -> Categorical:
        return Categorical(values=frozenset(values), include=False, universe=universe)

    def closed(self) -> Categorical:
        """``Exclude`` rewritten as ``Include`` when the universe is known; else unchanged."""
        if self.include or self.universe is None:
            return self
        return Categorical(values=self.universe - self.values, include=True, universe=self.universe)

    def is_empty(self) -> bool:
        c = self.closed()
        return c.include and not c.values

    def intersect(self, other: Domain) -> Categorical:
        o = _as(other, Categorical)
        u = self.universe or o.universe
        a, b = self.values, o.values
        if self.include and o.include:
            return Categorical(values=a & b, include=True, universe=u)
        if self.include:
            return Categorical(values=a - b, include=True, universe=u)
        if o.include:
            return Categorical(values=b - a, include=True, universe=u)
        return Categorical(values=a | b, include=False, universe=u)

    def subtract(self, other: Domain) -> tuple[Categorical, ...]:
        o = _as(other, Categorical)
        u = self.universe or o.universe
        a, b = self.values, o.values
        if self.include and o.include:
            piece = Categorical(values=a - b, include=True, universe=u)
        elif self.include:  # Include(A) \ Exclude(B) = Include(A ∩ B)
            piece = Categorical(values=a & b, include=True, universe=u)
        elif o.include:  # Exclude(A) \ Include(B) = Exclude(A ∪ B)
            piece = Categorical(values=a | b, include=False, universe=u)
        else:  # Exclude(A) \ Exclude(B) = Include(B \ A)
            piece = Categorical(values=b - a, include=True, universe=u)
        return () if piece.is_empty() else (piece,)

    def contains(self, other: Domain) -> bool:
        o = _as(other, Categorical)
        if o.is_empty():
            return True
        a, b = self.closed(), o.closed()
        if a.include and b.include:
            return b.values <= a.values
        if not a.include and not b.include:
            return a.values <= b.values
        if not a.include and b.include:
            return not (a.values & b.values)
        return False  # Include ⊇ Exclude needs a closed universe; without one, say no

    def contains_point(self, x: Point) -> bool:
        return (x in self.values) if self.include else (x not in self.values)

    def representative(self) -> Point:
        if self.include:
            return _first(self.values)
        if NA not in self.values:
            return NA
        if self.universe is not None:
            return _first(self.universe - self.values)
        for cand in ("x", "y", "z"):
            if cand not in self.values:
                return cand
        return NA

    def to_smt(self, term: z3.ExprRef, present: z3.BoolRef) -> z3.BoolRef:
        concrete = sorted((v for v in self.values if v is not NA), key=_sort_key)
        has_na = NA in self.values
        if self.include:
            parts = [z3.And(present, term == _lit(term, v)) for v in concrete]
            if has_na:
                parts.append(z3.Not(present))
            return z3.Or(*parts) if parts else z3.BoolVal(False)
        parts = [z3.Or(z3.Not(present), term != _lit(term, v)) for v in concrete]
        if has_na:
            parts.append(present)
        return z3.And(*parts) if parts else z3.BoolVal(True)

    def text(self) -> str:
        if self.is_empty():
            return "nothing"
        shown = ", ".join(_show(v) for v in sorted(self.values, key=_sort_key))
        if self.include:
            return f"= {shown}" if len(self.values) == 1 else f"∈ {{{shown}}}"
        if not self.values:
            return "any"
        return f"≠ {shown}" if len(self.values) == 1 else f"∉ {{{shown}}}"


BOOL_UNIVERSE: frozenset[Point] = frozenset({True, False, NA})


def boolean(*values: Point) -> Categorical:
    """A boolean axis — plan §4.4: the categorical algebra over ``{true, false, NA}``."""
    return Categorical(values=frozenset(values), include=True, universe=BOOL_UNIVERSE)


def _first(values: frozenset[Point]) -> Point:
    return next(iter(sorted(values, key=_sort_key)), NA)


def _sort_key(v: Point) -> tuple[int, str]:
    if v is NA:
        return (2, "")
    if isinstance(v, bool):
        return (1, str(v))
    return (0, str(v))


def _show(v: Point) -> str:
    return "missing" if v is NA else (str(v) if isinstance(v, bool | int) else f'"{v}"')


def _lit(term: z3.ExprRef, v: Point) -> z3.ExprRef:
    if isinstance(v, bool):
        return z3.BoolVal(v)
    if isinstance(v, int):
        return z3.IntVal(v)
    return z3.StringVal(str(v))


def _as(value: Domain, kind: type) -> Domain:
    if not isinstance(value, kind):
        raise TypeError(f"axis type mismatch: {kind.__name__} against {type(value).__name__}")
    return value
