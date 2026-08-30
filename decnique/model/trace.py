"""Multi-event trace AST shared by the DSL parser, front-ends and encoders (plan §5.3, §3.7).

A :class:`TraceSpec` is the body of a detection: event variables with single-event
predicates, joins, grouping, a window, ordering, outcome aggregates and a condition
over counts and aggregates.  A single-event rule is the ``n = 1`` case with condition
``#e >= 1``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from decnique.model.predicates import Pred, QField
from decnique.model.predicates import referenced_fields as pred_fields

AggFn = Literal["sum", "max", "min", "count", "count_distinct"]
WindowSide = Literal["around", "before", "after"]


@dataclass(frozen=True, slots=True)
class EventVar:
    name: str
    pred: Pred


@dataclass(frozen=True, slots=True)
class Join:
    left: QField
    right: QField


@dataclass(frozen=True, slots=True)
class Window:
    seconds: int
    anchor: str | None = None
    side: WindowSide = "around"


@dataclass(frozen=True, slots=True)
class AggCall:
    fn: AggFn
    arg: QField | None = None


@dataclass(frozen=True, slots=True)
class AggConst:
    value: int


@dataclass(frozen=True, slots=True)
class AggRef:
    name: str


@dataclass(frozen=True, slots=True)
class AggIf:
    cond: Pred
    then: AggExpr
    else_: AggExpr


@dataclass(frozen=True, slots=True)
class AggBin:
    op: Literal["+", "-", "*", "/"]
    left: AggExpr
    right: AggExpr


AggExpr = AggCall | AggConst | AggRef | AggIf | AggBin


@dataclass(frozen=True, slots=True)
class Count:
    """``#var op n``."""

    var: str
    op: str
    n: int


@dataclass(frozen=True, slots=True)
class AggCmp:
    """``name op n`` where ``name`` is an aggregate."""

    name: str
    op: str
    n: int


@dataclass(frozen=True, slots=True)
class CAnd:
    children: tuple[CondExpr, ...]


@dataclass(frozen=True, slots=True)
class COr:
    children: tuple[CondExpr, ...]


@dataclass(frozen=True, slots=True)
class CNot:
    child: CondExpr


@dataclass(frozen=True, slots=True)
class CTrue:
    pass


@dataclass(frozen=True, slots=True)
class CUnknown:
    """A part of the condition a front-end could not translate.  It evaluates to *don't-know*,
    so a rule whose condition was only partly understood can never be claimed to fire or not
    fire for certain (honesty invariant #1 — dropping the part would broaden the rule)."""

    label: str


CondExpr = Count | AggCmp | CAnd | COr | CNot | CTrue | CUnknown


@dataclass(frozen=True, slots=True)
class RuleOptions:
    allow_zero_values: bool = False
    extra: tuple[tuple[str, str | int | bool], ...] = ()


@dataclass(frozen=True, slots=True)
class TraceSpec:
    events: tuple[EventVar, ...]
    joins: tuple[Join, ...] = ()
    group_by: tuple[QField, ...] = ()
    window: Window | None = None
    order: tuple[str, ...] = ()
    aggregates: tuple[tuple[str, AggExpr], ...] = ()
    condition: CondExpr = field(default_factory=CTrue)
    options: RuleOptions = field(default_factory=RuleOptions)

    @property
    def event_names(self) -> tuple[str, ...]:
        return tuple(e.name for e in self.events)

    def event(self, name: str) -> EventVar:
        for e in self.events:
            if e.name == name:
                return e
        raise KeyError(name)

    @property
    def is_single_event(self) -> bool:
        return (
            len(self.events) == 1
            and not self.joins
            and not self.group_by
            and self.window is None
            and not self.aggregates
            and self.condition == Count(self.events[0].name, ">=", 1)
        )

    @property
    def aggregate_map(self) -> dict[str, AggExpr]:
        return dict(self.aggregates)


def single_event(name: str, pred: Pred, options: RuleOptions | None = None) -> TraceSpec:
    return TraceSpec(
        events=(EventVar(name, pred),),
        condition=Count(name, ">=", 1),
        options=options or RuleOptions(),
    )


# --- monotonicity and minimal instantiation size (§3.7) ---------------------------------

_MONOTONE_OPS = {">", ">="}


def is_monotone(c: CondExpr, aggregates: dict[str, AggExpr] | None = None) -> bool:
    """True iff adding events can never turn the condition from true to false."""
    aggregates = aggregates or {}
    if isinstance(c, CTrue):
        return True
    if isinstance(c, Count):
        return c.op in _MONOTONE_OPS
    if isinstance(c, AggCmp):
        agg = aggregates.get(c.name)
        if c.op not in _MONOTONE_OPS:
            return False
        # sum/count/count_distinct/max grow with more events; min does not.
        return _agg_monotone(agg)
    if isinstance(c, CNot):
        return False
    if isinstance(c, CAnd | COr):
        return all(is_monotone(x, aggregates) for x in c.children)
    return False


def _agg_monotone(agg: AggExpr | None) -> bool:
    if agg is None:
        return False
    if isinstance(agg, AggCall):
        return agg.fn in {"sum", "count", "count_distinct", "max"}
    if isinstance(agg, AggConst):
        return True
    if isinstance(agg, AggBin):
        if agg.op in {"+", "*"}:
            return _agg_monotone(agg.left) and _agg_monotone(agg.right)
        return isinstance(agg.right, AggConst) and _agg_monotone(agg.left)
    return False


def minimal_counts(spec: TraceSpec) -> dict[str, int]:
    """``N_v``: the smallest number of copies of each event variable that can satisfy
    the condition."""
    counts = {e.name: 1 for e in spec.events}
    aggs = spec.aggregate_map

    def need(c: CondExpr) -> None:
        if isinstance(c, Count):
            n = _min_for(c.op, c.n)
            counts[c.var] = max(counts.get(c.var, 1), n)
        elif isinstance(c, AggCmp):
            agg = aggs.get(c.name)
            if isinstance(agg, AggCall) and agg.fn in {"count", "count_distinct"} and agg.arg:
                var = agg.arg[0] or spec.events[0].name
                counts[var] = max(counts.get(var, 1), _min_for(c.op, c.n))
        elif isinstance(c, CAnd | COr):
            for x in c.children:
                need(x)
        elif isinstance(c, CNot):
            need(c.child)

    need(spec.condition)
    return counts


def _min_for(op: str, n: int) -> int:
    if op == ">":
        return max(n + 1, 1)
    if op in {">=", "="}:
        return max(n, 1)
    return 1


def instantiation_size(spec: TraceSpec) -> int:
    return sum(minimal_counts(spec).values())


def referenced_fields(spec: TraceSpec, var: str) -> frozenset[str]:
    """Fields of event variable ``var`` referenced anywhere in the spec (predicate, joins,
    group_by, aggregates)."""
    out: set[str] = set()
    ev = spec.event(var)
    for v, f in pred_fields(ev.pred):
        if v in (None, var):
            out.add(f)
    for j in spec.joins:
        for v, f in (j.left, j.right):
            if v == var:
                out.add(f)
    for v, f in spec.group_by:
        if v in (None, var):
            out.add(f)
    for _, agg in spec.aggregates:
        out |= _agg_fields(agg, var)
    return frozenset(out)


def _agg_fields(agg: AggExpr, var: str) -> set[str]:
    if isinstance(agg, AggCall):
        return {agg.arg[1]} if agg.arg and agg.arg[0] in (None, var) else set()
    if isinstance(agg, AggIf):
        out = {f for v, f in pred_fields(agg.cond) if v in (None, var)}
        return out | _agg_fields(agg.then, var) | _agg_fields(agg.else_, var)
    if isinstance(agg, AggBin):
        return _agg_fields(agg.left, var) | _agg_fields(agg.right, var)
    return set()


def condition_refs(c: CondExpr) -> tuple[set[str], set[str]]:
    """(event variables counted, aggregate names compared) in a condition."""
    vars_: set[str] = set()
    aggs: set[str] = set()

    def walk(x: CondExpr) -> None:
        if isinstance(x, Count):
            vars_.add(x.var)
        elif isinstance(x, AggCmp):
            aggs.add(x.name)
        elif isinstance(x, CAnd | COr):
            for y in x.children:
                walk(y)
        elif isinstance(x, CNot):
            walk(x.child)

    walk(c)
    return vars_, aggs
