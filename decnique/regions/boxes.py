"""Boxes and the hole computation — the coverage-gap plan §4.8, §7.1 and §7.3.

A **box** is a product of per-axis constraints: one :mod:`~decnique.regions.domains` value per
axis, and an axis the box does not mention is the whole axis (``TOP``), *including* ``NA``.
A rule is a finite union of boxes; a candidate's reachable set is one box (the plan's
"box-type" case).  The hole computation is then a set difference between unions of boxes,
carried out one rule at a time:

    holes = [candidate];  for each rule box P:  holes = ⋃ box_subtract(H, P)

:func:`box_subtract` splits ``H \\ P`` into **disjoint** pieces — one per axis, each taking the
part of that axis outside ``P`` while the axes already handled are pinned to ``H ∩ P``.  Because
the pieces are disjoint by construction, holes are never double-counted and the list never has
to be re-normalised.

Everything here is exact.  All the approximation in the system happens earlier, when a rule is
compiled to boxes (:mod:`decnique.regions.compile`), and it always goes in the one safe
direction: a rule may be made *smaller*, never larger, so a hole can be invented but never lost.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from decnique.regions.domains import NA, Categorical, Domain, Numeric, Point

DEFAULT_MAX_HOLES = 10_000  # plan D8: beyond this the interval backend hands over to SMT


@dataclass(frozen=True, slots=True)
class Axis:
    """One dimension of the space a candidate is measured in."""

    name: str
    top: Domain
    unit: str = ""  # "s" for durations — shown in the report, never used in the algebra
    doc: str = ""

    def numeric(self) -> bool:
        return isinstance(self.top, Numeric)


@dataclass(frozen=True, slots=True)
class Space:
    """The ordered list of axes.  Fixing the order makes :func:`box_subtract` deterministic,
    which in turn makes every reported hole reproducible."""

    axes: tuple[Axis, ...]

    def __post_init__(self) -> None:
        if len({a.name for a in self.axes}) != len(self.axes):
            raise ValueError("duplicate axis name")

    def axis(self, name: str) -> Axis:
        for a in self.axes:
            if a.name == name:
                return a
        raise KeyError(name)

    def names(self) -> tuple[str, ...]:
        return tuple(a.name for a in self.axes)

    def box(self, constraints: Mapping[str, Domain] | None = None) -> Box:
        return Box.of(self, constraints or {})

    def top(self) -> Box:
        return Box(space=self, values=())


@dataclass(frozen=True, slots=True)
class Box:
    """A product of per-axis constraints.  An axis missing from ``values`` is the whole axis."""

    space: Space
    values: tuple[tuple[str, Domain], ...]  # sorted by axis order; only non-TOP axes are kept

    @staticmethod
    def of(space: Space, constraints: Mapping[str, Domain]) -> Box:
        kept = []
        for name in space.names():
            axis = space.axis(name)
            v = constraints.get(name)
            if v is None:
                continue
            v = _bind(axis, v)
            if _is_top(axis, v):
                continue
            kept.append((name, v))
        return Box(space=space, values=tuple(kept))

    def get(self, name: str) -> Domain:
        for n, v in self.values:
            if n == name:
                return v
        return self.space.axis(name).top

    def with_axis(self, name: str, value: Domain) -> Box:
        return Box.of(self.space, {**dict(self.values), name: value})

    def is_empty(self) -> bool:
        return any(v.is_empty() for _, v in self.values)

    def intersect(self, other: Box) -> Box:
        return Box.of(
            self.space, {n: self.get(n).intersect(other.get(n)) for n in self.space.names()}
        )

    def contains(self, other: Box) -> bool:
        if other.is_empty():
            return True
        return all(self.get(n).contains(other.get(n)) for n in self.space.names())

    def contains_point(self, point: Mapping[str, Point]) -> bool:
        return all(self.get(n).contains_point(point.get(n, NA)) for n in self.space.names())

    def escape_axes(self, other: Box) -> tuple[str, ...]:
        """Axes on which ``self`` reaches past ``other`` — the plan's escape set E(C, R)."""
        return tuple(n for n in self.space.names() if not other.get(n).contains(self.get(n)))

    def witness(self) -> dict[str, Point]:
        """One point of the box, per axis (plan §7.3: every hole is reported with a witness)."""
        return {n: self.get(n).representative() for n in self.space.names()}

    def text(self) -> str:
        if self.is_empty():
            return "nothing"
        parts = []
        for name, v in self.values:
            unit = self.space.axis(name).unit
            parts.append(f"{name} {v.text()}{unit}")
        return "  ∧  ".join(parts) or "anything"


def _is_top(axis: Axis, value: Domain) -> bool:
    return value.contains(axis.top) and axis.top.contains(value)


def _bind(axis: Axis, value: Domain) -> Domain:
    """The closed value list is a property of the *axis*, not of one constraint.  A compiler
    writing ``method = "SetIamPolicy"`` has no reason to know it, so the box attaches it here;
    without this, a closed axis quietly behaves like an open one and containment answers no
    where it should answer yes."""
    if (
        isinstance(value, Categorical)
        and value.universe is None
        and isinstance(axis.top, Categorical)
        and axis.top.universe is not None
    ):
        return replace(value, universe=axis.top.universe)
    return value


# --- the difference of two boxes — plan §7.3 -------------------------------------------------


def box_subtract(h: Box, p: Box) -> tuple[Box, ...]:
    """``h \\ p`` as disjoint boxes.

    At most one piece per axis for a categorical axis and two for a numeric one, so a candidate
    with ``dim`` axes yields at most ``2·dim`` pieces per rule.  ``prefix`` walks the axes
    pinning each handled axis to ``h ∩ p``, which is what makes the pieces disjoint: piece *i*
    disagrees with ``p`` on axis *i* while agreeing on every axis before it.
    """
    if h.intersect(p).is_empty():
        return (h,)
    pieces: list[Box] = []
    prefix = h
    for name in h.space.names():
        hv, pv = h.get(name), p.get(name)
        for part in hv.subtract(pv):
            piece = prefix.with_axis(name, part)
            if not piece.is_empty():
                pieces.append(piece)
        prefix = prefix.with_axis(name, hv.intersect(pv))
    return tuple(pieces)


@dataclass(frozen=True, slots=True)
class Difference:
    """The result of subtracting a union of boxes from one box."""

    holes: tuple[Box, ...]
    overflowed: bool = False  # the hole cap was hit; the list is a prefix, not the whole set

    @property
    def covered(self) -> bool:
        return not self.holes and not self.overflowed


def subtract_all(
    region: Box, cover: tuple[Box, ...], *, max_holes: int = DEFAULT_MAX_HOLES
) -> Difference:
    """``region \\ ⋃cover``.  Rules are applied largest-overlap first, which tends to empty the
    hole list fastest; on overflow the caller falls back to the SMT backend (plan §7.3)."""
    holes: list[Box] = [region] if not region.is_empty() else []
    ordered = sorted(cover, key=lambda p: _overlap_rank(region, p), reverse=True)
    for p in ordered:
        if not holes:
            break
        nxt: list[Box] = []
        for h in holes:
            nxt.extend(box_subtract(h, p))
            if len(nxt) > max_holes:
                return Difference(holes=tuple(nxt[:max_holes]), overflowed=True)
        holes = nxt
    return Difference(holes=tuple(holes))


def _overlap_rank(region: Box, p: Box) -> int:
    """How much of ``region`` a rule box can remove — the count of axes it does not constrain
    past.  Cheap and type-free; it only decides the order, never the answer."""
    inter = region.intersect(p)
    if inter.is_empty():
        return -1
    return sum(1 for n in region.space.names() if p.get(n).contains(region.get(n)))


# --- pairwise classification — plan §7.1 -----------------------------------------------------

DISJOINT, COVERED, INSIDE, PARTIAL = "disjoint", "covered", "inside", "partial"


def classify(candidate: Box, rule: Box) -> str:
    """How a candidate sits against one rule box: does it never meet it, does the rule swallow
    it whole, is the rule narrower than the candidate, or do they overlap in part?"""
    if candidate.intersect(rule).is_empty():
        return DISJOINT
    if rule.contains(candidate):
        return COVERED
    if candidate.contains(rule):
        return INSIDE
    return PARTIAL


# --- convenience constructors used by the compiler and the front-ends ------------------------


def numeric_axis(name: str, unit: str = "", doc: str = "") -> Axis:
    return Axis(name=name, top=Numeric.top(), unit=unit, doc=doc)


def categorical_axis(
    name: str, universe: frozenset[Point] | None = None, doc: str = ""
) -> Axis:
    return Axis(name=name, top=Categorical.top(universe), doc=doc)
