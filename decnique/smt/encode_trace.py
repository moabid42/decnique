"""Bounded symbolic unrolling of a candidate footprint (plan §M3).

A footprint has *fixed* ``repeat`` counts, so the number of events is bounded and the
unrolling is sound: allocate exactly ``repeat`` symbolic occurrences per :class:`Step`, each a
:class:`~decnique.smt.encode_event.SymEvent` whose ``method`` is pinned to the step and whose
``time`` (and other fields) are symbolic.  This module builds:

* :func:`footprint_constraints` — the trace realizes the footprint (``within`` / ``distinct`` /
  ``order`` / ``span``).  Exact.
* :func:`rule_evasion` — ``¬Fires(R, τ)`` for the tractable single-variable count/window rule
  class, encoded to match the M0 oracle *exactly*; other rules are reported ``exact=False`` and
  left to concrete replay (Invariant #3).

The M0 window semantics this mirrors: with no ``group by``, all matched events form one group,
which is gated by ``window`` (``around``: every pair within ``W``) and only then counted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from decnique.model.predicates import referenced_fields
from decnique.model.trace import Count, CTrue, TraceSpec
from decnique.smt.encode_event import SymEvent
from decnique.smt.encode_pred import Encoder, _ordered_z3


@dataclass
class Occurrence:
    idx: int
    step_id: str
    method: str
    ev: SymEvent

    @property
    def time(self) -> z3.ExprRef:
        return self.ev.term("time")


@dataclass
class SymTrace:
    occs: tuple[Occurrence, ...]
    share: tuple[str, ...] = ("principal",)

    def of_step(self, step_id: str) -> tuple[Occurrence, ...]:
        return tuple(o for o in self.occs if o.step_id == step_id)


def build_trace(fp, share: tuple[str, ...] = ("principal",)) -> SymTrace:  # type: ignore[no-untyped-def]
    occs: list[Occurrence] = []
    i = 0
    for step in fp.steps:
        for _ in range(max(step.repeat, 1)):
            occs.append(Occurrence(i, step.id, step.method, SymEvent(prefix=f"o{i}")))
            i += 1
    return SymTrace(occs=tuple(occs), share=share)


def _abs_le(d: z3.ExprRef, w: int) -> z3.BoolRef:
    return z3.And(d <= z3.IntVal(w), d >= z3.IntVal(-w))


def footprint_constraints(trace: SymTrace, fp, catalog=None) -> list[z3.BoolRef]:  # type: ignore[no-untyped-def]
    cons: list[z3.BoolRef] = []
    for occ in trace.occs:
        cons.append(occ.ev.term("method") == z3.StringVal(occ.method))
        cons.append(occ.ev.present("method"))
        cons.append(occ.time >= z3.IntVal(0))
        # realism invariants (plan §M3): a real event fixes service/product_name by its method,
        # and a feasible actor's action is authorized (granted), so the solver cannot propose an
        # unrealistic schedule that evades a rule only by mangling those fields.
        if catalog is not None:
            for path, value in catalog.field_invariants(occ.method).items():
                cons.append(occ.ev.term(path) == z3.StringVal(value))
            cons.append(occ.ev.term("granted") == z3.BoolVal(True))

    steps = {s.id: s for s in fp.steps}
    for step in fp.steps:
        group = trace.of_step(step.id)
        if step.within_seconds is not None:
            for a in range(len(group)):
                for b in range(a + 1, len(group)):
                    cons.append(_abs_le(group[a].time - group[b].time, step.within_seconds))
        for qf in step.distinct:
            path = qf[1]
            for occ in group:
                cons.append(occ.ev.present(path))
            for a in range(len(group)):
                for b in range(a + 1, len(group)):
                    cons.append(group[a].ev.term(path) != group[b].ev.term(path))

    # order: for consecutive named steps a < b, some occurrence of a precedes some of b
    for a_id, b_id in zip(fp.order, fp.order[1:]):
        a_occs, b_occs = trace.of_step(a_id), trace.of_step(b_id)
        if a_occs and b_occs:
            cons.append(z3.Or(*[oa.time < ob.time for oa in a_occs for ob in b_occs]))

    if fp.span_seconds is not None:
        for a in range(len(trace.occs)):
            for b in range(a + 1, len(trace.occs)):
                cons.append(_abs_le(trace.occs[a].time - trace.occs[b].time, fp.span_seconds))

    # shared fields (e.g. principal) equal across all occurrences
    for field_path in trace.share:
        for occ in trace.occs[1:]:
            cons.append(occ.ev.term(field_path) == trace.occs[0].ev.term(field_path))
            cons.append(occ.ev.present(field_path))
        if trace.occs:
            cons.append(trace.occs[0].ev.present(field_path))
    return cons


def is_rate_rule(spec: TraceSpec) -> bool:
    """The tractable evasion class: one variable, no joins/group-by/aggregates/order, a single
    ``Count`` (or ``CTrue``) condition, and no anchored window."""
    return (
        len(spec.events) == 1
        and not spec.joins
        and not spec.group_by
        and not spec.aggregates
        and not spec.order
        and isinstance(spec.condition, (Count, CTrue))
        and (spec.window is None or spec.window.side == "around")
    )


def _match_formula(occ: Occurrence, spec: TraceSpec) -> tuple[z3.BoolRef, bool]:
    """Membership of one occurrence in the rule's single event variable, with the zero-value
    guard — mirrors :func:`decnique.eval.trace_eval.match_event_var`.  Returns (formula, exact)."""
    var = spec.events[0]
    enc = Encoder(ev=occ.ev)
    body = enc.pred(var.pred)
    exact = not enc.approx
    if not spec.options.allow_zero_values:
        guard = [occ.ev.present(path) for _, path in referenced_fields(var.pred)]
        if guard:
            body = z3.And(body, *guard)
    return body, exact


def rule_evasion(trace: SymTrace, spec: TraceSpec) -> tuple[z3.BoolRef | None, bool]:
    """``¬Fires(R, τ)`` for a rate rule, encoded to match M0 exactly.

    Returns ``(constraint, exact)``.  ``exact=False`` means the rule (or its predicate) is outside
    the tractable class; the caller must not rely on the constraint and instead lets concrete
    replay decide.  ``constraint is None`` means the rule can never fire on this trace (pruned)."""
    if not is_rate_rule(spec):
        return None, False
    matched: list[z3.BoolRef] = []
    times: list[z3.ExprRef] = []
    exact = True
    for occ in trace.occs:
        m, ok = _match_formula(occ, spec)
        exact = exact and ok
        matched.append(m)
        times.append(occ.time)
    if not matched:
        return None, exact

    cond = spec.condition
    if isinstance(cond, CTrue):
        count_ok: z3.BoolRef = z3.Or(*matched)
    else:  # Count
        count = z3.Sum([z3.If(m, z3.IntVal(1), z3.IntVal(0)) for m in matched])
        count_ok = _ordered_z3(cond.op, count, z3.IntVal(cond.n))

    if spec.window is None:
        fire = count_ok
    else:
        w = spec.window.seconds
        allfit = [
            z3.Implies(z3.And(matched[i], matched[j]), _abs_le(times[i] - times[j], w))
            for i in range(len(matched))
            for j in range(i + 1, len(matched))
        ]
        fire = z3.And(count_ok, *allfit) if allfit else count_ok
    return z3.Not(fire), exact
