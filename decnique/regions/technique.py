"""A technique's holes as regions — the coverage-gap plan §6, §7.1–§7.2 and §9.1.

``ask stealth`` answers "can this technique be run so that no rule fires?" with *one* schedule.
This module answers the wider question the plan asks: **over which runs of the technique does no
rule fire?**  The answer is a region over the technique's own free variables, and the schedule
``ask stealth`` already produced is one point inside it.

The variable space (plan §6.2) of a single-step footprint is small — which is the whole reason
the box machinery is worth using:

===========  ==========================================================================
``count``    how many times the step is performed (``repeat``)
``span``     over how many seconds, from the first event to the last (``span``)
one axis     per event field the footprint pins or a rule tests
===========  ==========================================================================

Rules are projected into that space (§7.2).  A single-event or rate rule fires exactly when
enough matching events fall inside its window, and because the occurrences of one step share
the field values the technique pins, either all of them match the rule's predicate or none do.
So the rule covers the box *its predicate* ∧ *the counts that trip it* ∧ *the spans short enough
to fit its window*.  Everything outside the class the engine encodes exactly — joins, group-by,
aggregates, anchored windows — is excluded and listed, never approximated (§5.4).

The result is deliberately conservative in one direction: candidates may be widened and rules
may be dropped, so a hole may be reported that a dropped rule would have covered (the report
says which), but a real hole is never lost.  The witness of every hole is replayed through the
concrete oracle before the hole is called verified, which is invariant #2 applied to a region.
"""

from __future__ import annotations

from dataclasses import dataclass

from decnique.detections import DetectionLibrary
from decnique.dsl.ast import Candidate
from decnique.env.model import Account
from decnique.eval import fires, matches_footprint
from decnique.model import event_fields as ef
from decnique.model.predicates import referenced_fields
from decnique.model.trace import Count, CTrue
from decnique.regions.backends import solve
from decnique.regions.boxes import Box, Space, categorical_axis, numeric_axis
from decnique.regions.compile import Unsupported, axis_for_field, compile_rule
from decnique.regions.domains import NA, Categorical, Domain, Numeric, Point
from decnique.smt.encode_trace import is_rate_rule

COUNT, SPAN = "count", "span"

FULLY_COVERED, PARTLY, UNCOVERED, UNDETERMINED = (
    "fully_covered",
    "partially_covered",
    "uncovered",
    "undetermined",
)


@dataclass(frozen=True, slots=True)
class Hole:
    """One region of runs that no rule observes, with a concrete run from inside it."""

    box: Box
    schedule: tuple[dict, ...]
    replayed: bool  # the schedule was rebuilt and no rule fired on it (invariant #2)

    def text(self) -> str:
        return self.box.text()


@dataclass(frozen=True, slots=True)
class Crossed:
    rule: str
    relation: str
    escape_axes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RegionReport:
    """The plan's §9.1 report for one candidate."""

    candidate: str
    status: str
    backend: str
    space: Space
    reachable: Box
    holes: tuple[Hole, ...] = ()
    crossed: tuple[Crossed, ...] = ()
    excluded_rules: tuple[tuple[str, str], ...] = ()
    caveats: tuple[str, ...] = ()
    overflowed: bool = False

    @property
    def approximate(self) -> bool:
        return bool(self.excluded_rules or self.caveats or self.overflowed)

    def summary(self) -> dict:
        return {
            "candidate": self.candidate,
            "status": self.status,
            "backend": self.backend,
            "axes": list(self.space.names()),
            "reachable": self.reachable.text(),
            "holes": [
                {"variables": h.text(), "witness": list(h.schedule), "replayed": h.replayed}
                for h in self.holes
            ],
            "crossed_rules": [
                {"rule": c.rule, "relation": c.relation, "escape_axes": list(c.escape_axes)}
                for c in self.crossed
            ],
            "excluded_rules": [{"id": r, "reason": why} for r, why in self.excluded_rules],
            "caveats": list(self.caveats),
        }


def region_report(
    candidate: Candidate,
    lib: DetectionLibrary,
    account: Account,
    *,
    backend: str = "auto",
    max_holes: int | None = None,
) -> RegionReport:
    """The whole evading set of one technique, over its free variables."""
    fp = candidate.footprint
    if len(fp.steps) != 1:
        return _undetermined(
            candidate,
            "this view models one step at a time; a footprint with several steps needs one axis "
            "set per step, which is a different space (plan §13)",
        )
    step = fp.steps[0]
    if step.distinct:
        return _undetermined(
            candidate,
            f"the step forces {', '.join(q[1] for q in step.distinct)} to differ between "
            "occurrences, so one axis cannot stand for the value they share",
        )

    space, caveats = _space(candidate, lib)
    reachable, more = _reachable(candidate, space)
    caveats += more
    if reachable.is_empty():
        return _undetermined(candidate, "the footprint's own payload is contradictory")

    covers, crossed, excluded = _project(candidate, lib, account, space, reachable)
    diff = solve(reachable, covers, backend=backend, max_holes=max_holes)

    holes = tuple(_hole(h, candidate, lib, account, space) for h in diff.holes)
    if diff.covered:
        status = FULLY_COVERED
    elif diff.overflowed:
        status = UNDETERMINED
    elif reachable.text() == (holes[0].text() if holes else None) and len(holes) == 1:
        status = UNCOVERED
    else:
        status = PARTLY
    return RegionReport(
        candidate=candidate.id,
        status=status,
        backend=backend,
        space=space,
        reachable=reachable,
        holes=holes,
        crossed=crossed,
        excluded_rules=excluded,
        caveats=caveats,
        overflowed=diff.overflowed,
    )


def _undetermined(candidate: Candidate, why: str) -> RegionReport:
    empty = Space(axes=(numeric_axis(COUNT), numeric_axis(SPAN, "s")))
    return RegionReport(
        candidate=candidate.id,
        status=UNDETERMINED,
        backend="none",
        space=empty,
        reachable=empty.top(),
        caveats=(why,),
    )


# --- the space (plan §6.2) --------------------------------------------------------------------


def _space(candidate: Candidate, lib: DetectionLibrary) -> tuple[Space, tuple[str, ...]]:
    """``count`` and ``span``, plus one axis per field the footprint pins or a rule reads.

    An axis gets a closed value list only from what the *candidate* can produce — the step's
    method, a field its payload pins to a literal.  Closing an axis on the rules' literals
    instead would be a claim that no other value exists, and on `principal` or `resource` that
    is plainly false.
    """
    step = candidate.footprint.steps[0]
    fields: set[str] = set()
    if step.where is not None:
        fields |= {p for _, p in referenced_fields(step.where)}
    for d in lib.detections:
        for var in d.spec.events:
            fields |= {p for _, p in referenced_fields(var.pred)}
    fields = {f for f in fields if ef.is_known_field(f)}
    fields.add("method")

    pinned = _pinned_values(step.where)
    axes = [numeric_axis(COUNT, doc="occurrences of the step"),
            numeric_axis(SPAN, "s", doc="first event to last")]
    caveats: list[str] = []
    for f in sorted(fields):
        if f == "method":
            axes.append(categorical_axis("method", frozenset({step.method, NA})))
        elif f in pinned:
            axes.append(categorical_axis(f, frozenset(pinned[f] | {NA})))
        else:
            axes.append(axis_for_field(f))
    return Space(axes=tuple(axes)), tuple(caveats)


def _pinned_values(where) -> dict[str, set[Point]]:  # type: ignore[no-untyped-def]
    """Fields the payload fixes to a literal — those axes have a knowable value list."""
    from decnique.model.predicates import All, Cmp, In

    out: dict[str, set[Point]] = {}
    todo = [where] if where is not None else []
    while todo:
        p = todo.pop()
        if isinstance(p, All):
            todo.extend(p.children)
        elif isinstance(p, Cmp) and p.op == "=" and not p.nocase:
            out.setdefault(p.field[1], set()).add(p.value)
        elif isinstance(p, In) and not p.nocase:
            out.setdefault(p.field[1], set()).update(p.values)
    return out


def _reachable(candidate: Candidate, space: Space) -> tuple[Box, tuple[str, ...]]:
    """The candidate's own box: the counts and spans it can run at, and the payload it sends."""
    fp = candidate.footprint
    step = fp.steps[0]
    n = max(step.repeat, 1)
    limit = fp.span_seconds if fp.span_seconds is not None else step.within_seconds
    cons: dict[str, Domain] = {
        COUNT: Numeric.exactly(n),
        SPAN: Numeric(lo=0, hi=limit if limit is not None else Numeric.top().hi, na=False),
        "method": Categorical.of(step.method),
    }
    caveats: list[str] = []
    if step.where is not None:
        rule = compile_rule(candidate.id, step.where, space)
        if rule.dropped or len(rule.boxes) != 1:
            # widening the candidate is the safe direction: it can only add runs that turn out
            # to be watched, never hide ones that are not
            caveats.append(
                "the technique's payload could not be turned into a single region "
                f"({'; '.join(rule.warnings) or 'it is a disjunction'}), so the report covers "
                "more runs than the technique really performs"
            )
        else:
            for name, value in rule.boxes[0].values:
                cons[name] = value
    return Box.of(space, cons), tuple(caveats)


# --- projecting the rules (plan §7.2) ----------------------------------------------------------


def _project(
    candidate: Candidate,
    lib: DetectionLibrary,
    account: Account,
    space: Space,
    reachable: Box,
) -> tuple[tuple[Box, ...], tuple[Crossed, ...], tuple[tuple[str, str], ...]]:
    step = candidate.footprint.steps[0]
    covers: list[Box] = []
    crossed: list[Crossed] = []
    excluded: list[tuple[str, str]] = []

    if not account.logged(step.method):
        excluded.append(
            ("(all rules)", f"{step.method} is not written to this account's audit log, so no "
                            "rule can see the technique at all")
        )
        return (), (), tuple(excluded)

    for d in lib.detections:
        if fires(d.spec, [], ref_lists=lib.ref_lists) is True:
            excluded.append((d.id, "fires on an empty trace, so it observes nothing"))
            continue
        if not is_rate_rule(d.spec):
            excluded.append((d.id, "outside the exactly-encoded class (join, group by, "
                                   "aggregate or anchored window)"))
            continue
        try:
            counts = _count_region(d.spec.condition)
        except Unsupported as e:
            excluded.append((d.id, str(e)))
            continue
        compiled = compile_rule(d.id, d.spec.events[0].pred, space)
        if compiled.dropped:
            excluded.append((d.id, "; ".join(compiled.warnings)))
            continue
        window = d.spec.window
        span = Numeric.at_most(window.seconds) if window is not None else Numeric.top()
        boxes = [
            b.intersect(space.box({COUNT: counts, SPAN: span}))
            for b in compiled.boxes
        ]
        boxes = [b for b in boxes if not b.is_empty()]
        if not boxes:
            continue
        covers.extend(boxes)
        from decnique.regions.boxes import DISJOINT, classify

        widest = min(boxes, key=lambda b: len(b.values))
        relation = classify(reachable, widest)
        if relation != DISJOINT:
            # "crosses" means the two sets actually meet (plan §2.3).  A rule that can never
            # fire on this technique is not a row in the report — on a real corpus that would
            # be every rule about every other service.
            crossed.append(
                Crossed(
                    rule=d.id,
                    relation=relation,
                    escape_axes=reachable.escape_axes(widest),
                )
            )
    return tuple(covers), tuple(crossed), tuple(excluded)


def _count_region(condition) -> Numeric:  # type: ignore[no-untyped-def]
    """How many matching events make the rule fire.  ``CTrue`` is "at least one"."""
    if isinstance(condition, CTrue):
        return Numeric.at_least(1)
    if isinstance(condition, Count):
        n, op = condition.n, condition.op
        if op == ">":
            return Numeric.at_least(n + 1)
        if op == ">=":
            return Numeric.at_least(n)
        if op == "<":
            return Numeric.at_most(n - 1)
        if op == "<=":
            return Numeric.at_most(n)
        if op == "=":
            return Numeric.exactly(n)
    raise Unsupported("a condition this view cannot read as a count")


# --- a run from inside a hole, replayed (invariant #2) ----------------------------------------


def _hole(
    box: Box, candidate: Candidate, lib: DetectionLibrary, account: Account, space: Space
) -> Hole:
    point = box.witness()
    schedule = _schedule(point, candidate, account, space)
    replayed = False
    if schedule:
        realized = matches_footprint(candidate.footprint, list(schedule), ref_lists=lib.ref_lists)
        verdicts = [fires(d.spec, list(schedule), ref_lists=lib.ref_lists) for d in lib.detections]
        replayed = realized is True and not any(v is True for v in verdicts)
    return Hole(box=box, schedule=schedule, replayed=replayed)


def _schedule(
    point: dict[str, Point], candidate: Candidate, account: Account, space: Space
) -> tuple[dict, ...]:
    """One concrete run from the middle of the region: ``count`` events spread evenly over
    ``span``, each carrying the field values the region fixes."""
    step = candidate.footprint.steps[0]
    n = int(point.get(COUNT) or 1)
    span = point.get(SPAN)
    total = int(span) if isinstance(span, int) else 0
    base: dict = {"method": step.method, "granted": True}
    for path, value in account.catalog.field_invariants(step.method).items():
        base[path] = value
    for name in space.names():
        if name in (COUNT, SPAN, "method"):
            continue
        v = point.get(name)
        if v is not NA and v is not None:
            _put(base, name, v)
    step_gap = (total // (n - 1)) if n > 1 else 0
    events = []
    for i in range(n):
        ev = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
        ev["time"] = i * step_gap if n > 1 else 0
        events.append(ev)
    if n > 1:
        events[-1]["time"] = total  # land exactly on the span the region names
    return tuple(events)


def _put(event: dict, path: str, value: Point) -> None:
    if ef.is_udm(path):
        event.setdefault("udm", {})[ef.udm_path(path)] = value
    elif path.startswith(ef.TAG_PREFIX):
        event.setdefault("tags", {})[path[len(ef.TAG_PREFIX):]] = value
    else:
        event[path] = value


__all__ = [
    "Crossed",
    "Hole",
    "RegionReport",
    "region_report",
]
