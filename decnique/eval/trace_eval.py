"""Concrete three-valued evaluator for multi-event detections and footprints (M0).

The entry points are :func:`fires` (does a :class:`TraceSpec` fire on an ordered event
list?) and :func:`matches_footprint` (does an event list realize a candidate
:class:`Footprint`?).  Both return :data:`~decnique.dsl.interpret.Tri` — ``True`` /
``False`` / ``None`` (don't know).

Semantics (a deliberately naive oracle, §M0 of the plan):

1. **Match.** Each :class:`EventVar` predicate is evaluated against every event with the
   same zero-value guard :func:`~decnique.dsl.interpret.observes` uses, yielding for each
   event a *definite* (``True``) or *possible* (``None``) membership; ``False`` drops it.
2. **Correlate & group.** ``join`` equalities are unioned into key classes; together with
   ``group by`` they partition matched (event, variable) instances into groups that agree
   on every key dimension.
3. **Window / order.** A group is gated by ``window`` (events fit the span / anchor side)
   and ``order`` (temporal order among the named variables).
4. **Aggregates & condition.** Counts (``#v``) and aggregates are computed per group as
   *intervals* ``[definite, possible]`` so uncertain membership folds to ``don't know``;
   the ``condition`` is evaluated over those intervals.
5. **Fire.** Three-valued OR across groups.

A single-event ``TraceSpec`` reduces to ``observes``: ``fires(spec, [e])`` equals
``observes(R, e)`` (asserted corpus-wide by the M0 tests).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any as AnyT

from decnique.dsl.ast import Footprint, Step
from decnique.dsl.interpret import (
    Event,
    RefLists,
    Tri,
    _MISSING,
    evaluate,
    field_value,
)
from decnique.model.predicates import QField, referenced_fields
from decnique.model.trace import (
    AggBin,
    AggCall,
    AggCmp,
    AggConst,
    AggExpr,
    AggIf,
    AggRef,
    CAnd,
    CNot,
    CondExpr,
    COr,
    Count,
    CTrue,
    EventVar,
    TraceSpec,
)

# An (event, variable, membership) instance produced by the match phase.
Instance = tuple[str, Event, Tri]
Group = list[Instance]
_WILDCARD = object()


# --- three-valued primitives ------------------------------------------------------------


def _and(a: Tri, b: Tri) -> Tri:
    if a is False or b is False:
        return False
    if a is None or b is None:
        return None
    return True


def _or_all(results: Iterable[Tri]) -> Tri:
    saw_none = False
    for r in results:
        if r is True:
            return True
        if r is None:
            saw_none = True
    return None if saw_none else False


def _not(a: Tri) -> Tri:
    return None if a is None else not a


def _cmp_interval(lo: float, hi: float, op: str, n: float) -> Tri:
    """Truth of ``x op n`` as ``x`` ranges over the integer interval ``[lo, hi]``."""
    if op in (">", ">="):
        if _ordered(op, lo, n):
            return True
        if not _ordered(op, hi, n):
            return False
        return None
    if op in ("<", "<="):
        if _ordered(op, hi, n):
            return True
        if not _ordered(op, lo, n):
            return False
        return None
    if op == "=":
        if lo == hi == n:
            return True
        return None if lo <= n <= hi else False
    if op == "!=":
        if lo == hi == n:
            return False
        return None if lo <= n <= hi else True
    raise ValueError(f"unknown comparison op {op!r}")


def _ordered(op: str, a: AnyT, b: AnyT) -> bool:
    return {
        "=": a == b,
        "!=": a != b,
        "<": a < b,
        "<=": a <= b,
        ">": a > b,
        ">=": a >= b,
    }[op]


# --- match phase ------------------------------------------------------------------------


def match_event_var(
    ev: EventVar,
    event: Event,
    *,
    allow_zero_values: bool = False,
    ref_lists: RefLists | None = None,
) -> Tri:
    """Membership of ``event`` in event variable ``ev`` — mirrors the per-variable body of
    :func:`decnique.dsl.interpret.observes`, including the zero-value guard (every
    referenced field must be present unless ``allow_zero_values``)."""
    pred = ev.pred
    if not allow_zero_values:
        for var, path in referenced_fields(pred):
            if var not in (None, ev.name):
                continue
            raw = field_value(event, (var, path))
            if raw is _MISSING or raw is None:
                return False
    return evaluate(pred, event, ref_lists=ref_lists)


def _matched(
    spec: TraceSpec, events: Sequence[Event], ref_lists: RefLists | None
) -> dict[str, list[tuple[Event, Tri]]]:
    allow = spec.options.allow_zero_values
    out: dict[str, list[tuple[Event, Tri]]] = {}
    for ev in spec.events:
        hits: list[tuple[Event, Tri]] = []
        for e in events:
            tri = match_event_var(ev, e, allow_zero_values=allow, ref_lists=ref_lists)
            if tri is not False:
                hits.append((e, tri))
        out[ev.name] = hits
    return out


# --- correlation keys & grouping --------------------------------------------------------


class _UnionFind:
    def __init__(self) -> None:
        self._parent: dict[QField, QField] = {}

    def find(self, x: QField) -> QField:
        self._parent.setdefault(x, x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: QField, b: QField) -> None:
        self._parent[self.find(a)] = self.find(b)


def _key_dimensions(spec: TraceSpec) -> list[frozenset[QField]]:
    """Ordered key dimensions: join-connected field classes plus each ``group by`` field."""
    uf = _UnionFind()
    fields: list[QField] = []
    for j in spec.joins:
        uf.union(j.left, j.right)
        fields.extend((j.left, j.right))
    for g in spec.group_by:
        uf.find(g)
        fields.append(g)
    classes: dict[QField, set[QField]] = defaultdict(set)
    for f in fields:
        classes[uf.find(f)].add(f)
    return [frozenset(members) for members in classes.values()]


def _dim_value(event: Event, var: str, dim: frozenset[QField]) -> object:
    """The value event ``event`` (playing role ``var``) contributes to key dimension
    ``dim``, or ``_WILDCARD`` if this variable has no field in the dimension."""
    for dvar, path in dim:
        if dvar in (None, var):
            v = field_value(event, (dvar, path))
            return _WILDCARD if v is _MISSING else v
    return _WILDCARD


def _group(spec: TraceSpec, matched: dict[str, list[tuple[Event, Tri]]]) -> list[Group]:
    dims = _key_dimensions(spec)
    if not dims:
        flat: Group = [(v, e, t) for v, hits in matched.items() for (e, t) in hits]
        return [flat] if flat else []
    groups: dict[tuple[object, ...], Group] = defaultdict(list)
    for var, hits in matched.items():
        for e, tri in hits:
            key = tuple(_dim_value(e, var, d) for d in dims)
            groups[key].append((var, e, tri))
    return list(groups.values())


# --- window & order gates ---------------------------------------------------------------


def _time(event: Event) -> int | None:
    t = event.get("time")
    return int(t) if isinstance(t, int | float) else None


def _window_gate(spec: TraceSpec, group: Group) -> Tri:
    w = spec.window
    if w is None:
        return True
    times = [_time(e) for _, e, _ in group]
    if any(t is None for t in times):
        return None
    ts: list[int] = [t for t in times if t is not None]
    if not ts:
        return True
    if w.side == "around" or w.anchor is None:
        return (max(ts) - min(ts)) <= w.seconds
    anchors = [_time(e) for v, e, _ in group if v == w.anchor]
    anchors = [t for t in anchors if t is not None]
    if not anchors:
        return False
    for a in anchors:
        lo, hi = (a - w.seconds, a) if w.side == "before" else (a, a + w.seconds)
        if all(lo <= t <= hi for t in ts):
            return True
    return False


def _order_gate(spec: TraceSpec, group: Group) -> Tri:
    if not spec.order:
        return True
    by_var: dict[str, list[int | None]] = defaultdict(list)
    for v, e, _ in group:
        by_var[v].append(_time(e))
    result: Tri = True
    for a, b in zip(spec.order, spec.order[1:]):
        ta, tb = by_var.get(a, []), by_var.get(b, [])
        if not ta or not tb:
            return False
        if any(t is None for t in ta) or any(t is None for t in tb):
            result = None
            continue
        if not any(x < y for x in ta for y in tb):  # type: ignore[operator]
            return False
    return result


# --- aggregates & condition -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Interval:
    lo: float
    hi: float
    certain: bool = True


def _members(group: Group, arg: QField | None) -> tuple[list[Event], list[Event]]:
    """(definite, possible) events matching the aggregate argument's variable."""
    var = arg[0] if arg else None
    definite = [e for v, e, t in group if var in (None, v) and t is True]
    possible = [e for v, e, t in group if var in (None, v) and t is None]
    return definite, possible


def _nums(events: list[Event], path: str) -> tuple[list[float], bool]:
    vals: list[float] = []
    certain = True
    for e in events:
        raw = field_value(e, (None, path))
        if raw is _MISSING or raw is None:
            certain = False
            continue
        try:
            vals.append(float(raw))
        except (TypeError, ValueError):
            certain = False
    return vals, certain


def _agg_call(group: Group, agg: AggCall) -> _Interval:
    definite, possible = _members(group, agg.arg)
    if agg.fn == "count":
        return _Interval(len(definite), len(definite) + len(possible))
    if not agg.arg:
        return _Interval(0, 0, False)
    path = agg.arg[1]
    if agg.fn == "count_distinct":
        d = {field_value(e, (None, path)) for e in definite}
        d.discard(_MISSING)
        allv = {field_value(e, (None, path)) for e in definite + possible}
        allv.discard(_MISSING)
        return _Interval(len(d), len(allv))
    dv, dc = _nums(definite, path)
    pv, pc = _nums(possible, path)
    certain = dc and pc
    if agg.fn == "sum":  # numeric fields (bytes) are non-negative → monotone up
        lo = sum(x for x in dv)
        hi = lo + sum(x for x in pv if x > 0)
        return _Interval(lo, hi, certain)
    if agg.fn == "max":
        lo = max(dv) if dv else 0
        hi = max(dv + pv) if (dv or pv) else 0
        return _Interval(lo, hi, certain)
    if agg.fn == "min":
        lo = min(dv + pv) if (dv or pv) else 0
        hi = min(dv) if dv else (min(pv) if pv else 0)
        return _Interval(lo, hi, certain)
    return _Interval(0, 0, False)


def _agg_interval(group: Group, agg: AggExpr, aggregates: Mapping[str, AggExpr]) -> _Interval:
    if isinstance(agg, AggCall):
        return _agg_call(group, agg)
    if isinstance(agg, AggConst):
        return _Interval(agg.value, agg.value)
    if isinstance(agg, AggRef):
        ref = aggregates.get(agg.name)
        return _agg_interval(group, ref, aggregates) if ref is not None else _Interval(0, 0, False)
    if isinstance(agg, AggBin):
        left = _agg_interval(group, agg.left, aggregates)
        right = _agg_interval(group, agg.right, aggregates)
        return _bin_interval(agg.op, left, right)
    if isinstance(agg, AggIf):
        then = _agg_interval(group, agg.then, aggregates)
        else_ = _agg_interval(group, agg.else_, aggregates)
        return _Interval(min(then.lo, else_.lo), max(then.hi, else_.hi), False)
    return _Interval(0, 0, False)


def _bin_interval(op: str, a: _Interval, b: _Interval) -> _Interval:
    certain = a.certain and b.certain
    corners = [
        _apply(op, x, y)
        for x in (a.lo, a.hi)
        for y in (b.lo, b.hi)
        if not (op == "/" and y == 0)
    ]
    if not corners:
        return _Interval(0, 0, False)
    return _Interval(min(corners), max(corners), certain)


def _apply(op: str, x: float, y: float) -> float:
    return {"+": x + y, "-": x - y, "*": x * y, "/": x / y if y else 0.0}[op]


def _eval_cond(c: CondExpr, group: Group, aggregates: Mapping[str, AggExpr]) -> Tri:
    if isinstance(c, CTrue):
        return True
    if isinstance(c, Count):
        definite = sum(1 for v, _, t in group if v == c.var and t is True)
        possible = definite + sum(1 for v, _, t in group if v == c.var and t is None)
        return _cmp_interval(definite, possible, c.op, c.n)
    if isinstance(c, AggCmp):
        agg = aggregates.get(c.name)
        if agg is None:
            return None
        iv = _agg_interval(group, agg, aggregates)
        r = _cmp_interval(iv.lo, iv.hi, c.op, c.n)
        return None if (r is not None and not iv.certain) else r
    if isinstance(c, CAnd):
        out: Tri = True
        for x in c.children:
            out = _and(out, _eval_cond(x, group, aggregates))
        return out
    if isinstance(c, COr):
        return _or_all(_eval_cond(x, group, aggregates) for x in c.children)
    if isinstance(c, CNot):
        return _not(_eval_cond(c.child, group, aggregates))
    return None  # CUnknown: the front-end could not say


# --- public entry points ----------------------------------------------------------------


def fires(spec: TraceSpec, events: Sequence[Event], *, ref_lists: RefLists | None = None) -> Tri:
    """Three-valued: does ``spec`` fire on this ordered list of concrete events?"""
    matched = _matched(spec, events, ref_lists)
    aggregates = spec.aggregate_map
    groups = _group(spec, matched)
    if not groups:  # let count conditions like ``#e = 0`` see an empty group
        if isinstance(spec.condition, CTrue):
            return False  # nothing matched and nothing was asked of the count: no alert
        return _eval_cond(spec.condition, [], aggregates)
    per_group: list[Tri] = []
    for g in groups:
        gate = _and(_window_gate(spec, g), _order_gate(spec, g))
        per_group.append(_and(gate, _eval_cond(spec.condition, g, aggregates)))
    return _or_all(per_group)


def _step_interval(
    step: Step, events: Sequence[Event], ref_lists: RefLists | None
) -> tuple[_Interval, list[int | None]]:
    """Count of occurrences of ``step`` (as ``[definite, possible]``) and the timestamps of
    the events that could satisfy it, honouring ``repeat`` / ``within`` / ``distinct``."""
    definite: list[Event] = []
    possible: list[Event] = []
    for e in events:
        if e.get("method") != step.method:
            continue
        guard: Tri = True if step.where is None else evaluate(step.where, e, ref_lists=ref_lists)
        if guard is False:
            continue
        (definite if guard is True else possible).append(e)

    def _count(pool: list[Event]) -> int:
        pool = _within_filter(pool, step.within_seconds, step.repeat)
        if step.distinct:
            keys = {tuple(field_value(e, qf) for qf in step.distinct) for e in pool}
            return len(keys)
        return len(pool)

    lo = _count(definite)
    hi = _count(definite + possible)
    times = [_time(e) for e in definite + possible]
    return _Interval(lo, hi, True), times


def _within_filter(pool: list[Event], within_seconds: int | None, repeat: int) -> list[Event]:
    """If ``within_seconds`` is set, keep the largest subset of ``pool`` whose timestamps fit
    a single window of that length (so ``repeat`` occurrences must be close in time)."""
    if within_seconds is None:
        return pool
    timed = sorted((t for e in pool if (t := _time(e)) is not None))
    if len(timed) < len(pool):  # a missing timestamp — cannot bound the window
        return pool
    best = pool[:0]
    best_n = 0
    for i, start in enumerate(timed):
        n = sum(1 for t in timed[i:] if t - start <= within_seconds)
        if n > best_n:
            best_n = n
    # rebuild an event subset of size best_n (timestamps are the discriminator here)
    if best_n == 0:
        return []
    keep: list[Event] = []
    for i, start in enumerate(timed):
        window = [e for e in pool if (t := _time(e)) is not None and start <= t <= start + within_seconds]
        if len(window) == best_n:
            return window
    return keep or pool


def matches_footprint(
    fp: Footprint, events: Sequence[Event], *, ref_lists: RefLists | None = None
) -> Tri:
    """Three-valued: does this event list realize the candidate footprint ``fp``?"""
    result: Tri = True
    step_times: dict[str, list[int | None]] = {}
    for step in fp.steps:
        iv, times = _step_interval(step, events, ref_lists)
        step_times[step.id] = times
        result = _and(result, _cmp_interval(iv.lo, iv.hi, ">=", step.repeat))
        if result is False:
            return False

    for a, b in zip(fp.order, fp.order[1:]):
        ta = [t for t in step_times.get(a, []) if t is not None]
        tb = [t for t in step_times.get(b, []) if t is not None]
        if not ta or not tb:
            result = _and(result, None)
        elif not any(x < y for x in ta for y in tb):
            return False

    if fp.span_seconds is not None:
        all_times = [t for ts in step_times.values() for t in ts if t is not None]
        if all_times and (max(all_times) - min(all_times)) > fp.span_seconds:
            return False
        if any(t is None for ts in step_times.values() for t in ts):
            result = _and(result, None)
    return result
