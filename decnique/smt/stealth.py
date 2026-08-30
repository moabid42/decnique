"""Symbolic stealth over one technique — ``stealth_feasible`` of plan §M3.

``feasible(C)``        — does some principal hold every ``Required`` permission of ``C``?
``stealth_feasible(C)`` — is there a schedule τ that realizes ``C``'s footprint, reachable and
logged, on which **no** rule fires?

The solver proposes a schedule (event times, IPs, principal); the concrete M0 oracle
(:func:`decnique.eval.matches_footprint` + :func:`decnique.eval.fires`) is the arbiter.  A
schedule is returned only if it concretely realizes the footprint and no rule fires on it, so
``Evasive`` is sound.  ``AlwaysDetected`` (UNSAT) is a proof over the exactly-encoded rate rules;
rules outside that class add no constraint and are caught by replay, and if one is only
*don't-know* on the witness the verdict is flagged approximate (Invariant #1).

Three honesty rules, mirroring the coverage engine:

- a rule that fires on the *empty* trace (``#e < 5``) observes nothing and is left out — it
  would otherwise make every technique "always detected";
- a schedule blocked because the oracle answered *don't-know* (not *no*) on the footprint is an
  unproven block: an UNSAT after one is ``Exhausted``, never a proof;
- a footprint step whose method the account does not log (``Log``) is invisible to every rule;
  such steps are listed in ``Evasive.unlogged`` so the reader sees a logging gap, not a rule gap.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import z3

from decnique.detections import DetectionLibrary
from decnique.dsl.ast import Candidate
from decnique.env.model import Account
from decnique.eval import fires, matches_footprint
from decnique.model import event_fields as ef
from decnique.model.predicates import referenced_fields
from decnique.smt.encode_trace import (
    Occurrence,
    SymTrace,
    build_trace,
    footprint_constraints,
    rule_evasion,
)


@dataclass(frozen=True, slots=True)
class Evasive:
    """A concrete, replay-verified schedule that realizes the technique and evades every rule."""

    candidate: str
    schedule: tuple[dict, ...]
    principal: str
    approximate: bool
    unknown_rules: tuple[str, ...] = ()
    unlogged: tuple[str, ...] = ()  # footprint methods the account never writes to the audit log
    verdict: str = "evasive"


@dataclass(frozen=True, slots=True)
class AlwaysDetected:
    candidate: str
    caught_by: tuple[str, ...] = ()  # rate rules whose evasion was impossible (the UNSAT core)
    verdict: str = "always_detected"


@dataclass(frozen=True, slots=True)
class NotFeasible:
    candidate: str
    missing: tuple[str, ...] = ()
    verdict: str = "not_feasible"


@dataclass(frozen=True, slots=True)
class Exhausted:
    candidate: str
    verdict: str = "exhausted"


StealthResult = Evasive | AlwaysDetected | NotFeasible | Exhausted


def feasible(candidate: Candidate, account: Account) -> tuple[str, ...]:
    """Principals holding *every* Required permission of the candidate."""
    perms = tuple(r.permission for r in candidate.required)
    return account.principals_with_all(perms)


def _relevant_paths(candidate: Candidate, lib: DetectionLibrary) -> tuple[str, ...]:
    """Fields to decode into each schedule event.  Covers the footprint's own fields *and* every
    field any detection reads, plus the invariant fields, so the concrete replay that decides
    ``Evasive`` sees faithful events (not ones missing ``granted``/``product_name``)."""
    paths = set(ef.FIELD_NAMES)  # every closed-vocabulary field, so each schedule event is complete
    for step in candidate.footprint.steps:
        for qf in step.distinct:
            paths.add(qf[1])
        if step.where is not None:
            for _, p in referenced_fields(step.where):
                paths.add(p)
    for d in lib.detections:
        for e in d.spec.events:
            for _, p in referenced_fields(e.pred):
                paths.add(p)
    return tuple(sorted(paths))


def _put(event: dict, path: str, value) -> None:  # type: ignore[no-untyped-def]
    """Store a value where the concrete oracle reads it (``udm:``/``tags.`` are nested)."""
    if ef.is_udm(path):
        event.setdefault("udm", {})[ef.udm_path(path)] = value
    elif path.startswith(ef.TAG_PREFIX):
        event.setdefault("tags", {})[path[len(ef.TAG_PREFIX):]] = value
    else:
        event[path] = value


def _decode_event(occ: Occurrence, model: z3.ModelRef, paths: tuple[str, ...]) -> dict:
    ev = occ.ev
    out: dict = {"method": occ.method}
    for path in paths:
        if path == "method":
            continue
        pres = ev.present(path)
        present = z3.is_true(pres) or z3.is_true(model.eval(pres, model_completion=True))
        if not present:
            continue
        sort = ev.sort_of(path)
        v = model.eval(ev.term(path), model_completion=True)
        if sort in ("string", "strings"):
            _put(out, path, v.as_string())
        elif sort in ("int", "time"):
            _put(out, path, v.as_long())
        elif sort == "bool":
            _put(out, path, z3.is_true(v))
        elif sort == "ip":
            _put(out, path, str(ipaddress.IPv4Address(v.as_long() & 0xFFFFFFFF)))
        else:
            _put(out, path, v.as_string())
    return out


def _block(trace: SymTrace, model: z3.ModelRef, paths: tuple[str, ...]) -> z3.BoolRef:
    diffs: list[z3.BoolRef] = []
    for occ in trace.occs:
        for path in paths:
            term = occ.ev.term(path)
            diffs.append(term != model.eval(term, model_completion=True))
    return z3.Or(*diffs) if diffs else z3.BoolVal(False)


def stealth_feasible(
    candidate: Candidate,
    lib: DetectionLibrary,
    account: Account,
    *,
    max_refine: int = 64,
) -> StealthResult:
    principals = feasible(candidate, account)
    if not principals:
        missing = tuple(
            r.permission for r in candidate.required if not account.reachable(r.permission)
        )
        return NotFeasible(candidate.id, missing=missing)
    principal = principals[0]

    fp = candidate.footprint
    fp_methods = {s.method for s in fp.steps}
    trace = build_trace(fp, share=candidate.share)
    s = z3.Solver()
    s.set("random_seed", 0)  # reproducible schedules (plan §4)
    for c in footprint_constraints(trace, fp, account.catalog):
        s.add(c)
    # pin the shared principal to a feasible one
    if "principal" in candidate.share and trace.occs:
        s.add(trace.occs[0].ev.term("principal") == z3.StringVal(principal))

    # Log: an occurrence of an unlogged method never reaches a rule.
    visible = tuple(account.logged(o.method) for o in trace.occs)
    unlogged = tuple(sorted({o.method for o in trace.occs if not account.logged(o.method)}))
    # rules that fire on the empty trace observe nothing (see the module docstring)
    vacuous = {d.id for d in lib.detections if fires(d.spec, [], ref_lists=lib.ref_lists) is True}
    rules = [d for d in lib.detections if d.id not in vacuous]

    rate_specs = []
    approx_rules: list[str] = []
    track_of: dict[str, z3.BoolRef] = {}  # rule id → assumption literal gating its evasion clause
    for d in rules:
        # prune rules that literally cannot fire on the footprint's methods
        from decnique.dsl.interpret import spec_methods_literal

        lits = spec_methods_literal(d.spec)
        if lits and lits.isdisjoint(fp_methods):
            continue
        constraint, exact = rule_evasion(trace, d.spec, visible=visible)
        if constraint is not None and exact:
            track = z3.Bool(f"track.{d.id}")
            s.add(z3.Implies(track, constraint))
            track_of[d.id] = track
            rate_specs.append(d.spec)
        else:
            approx_rules.append(d.id)

    paths = _relevant_paths(candidate, lib)
    required = {p for st in fp.steps for p in account.catalog.required_fields(st.method)}
    paths = tuple(sorted(set(paths) | required))  # a real event carries these even if unread

    track_lits = list(track_of.values())
    by_track = {str(t): rid for rid, t in track_of.items()}
    unproven = False
    for _ in range(max_refine):
        if s.check(*track_lits) != z3.sat:
            if unproven:
                return Exhausted(candidate.id)
            core = {str(b) for b in s.unsat_core()}
            caught = tuple(sorted(rid for t, rid in by_track.items() if t in core))
            return AlwaysDetected(candidate.id, caught_by=caught)
        model = s.model()
        events = [_decode_event(o, model, paths) for o in trace.occs]
        realized = matches_footprint(fp, events, ref_lists=lib.ref_lists)
        if realized is not True:
            unproven = unproven or realized is None  # "don't know" is not a refutation
            s.add(_block(trace, model, paths))
            continue
        seen = [e for e, ok in zip(events, visible) if ok]  # what the audit log carries
        verdicts = {d.id: fires(d.spec, seen, ref_lists=lib.ref_lists) for d in rules}
        if any(v is True for v in verdicts.values()):
            s.add(_block(trace, model, paths))
            continue
        unknown = tuple(rid for rid, v in verdicts.items() if v is None)
        return Evasive(
            candidate=candidate.id,
            schedule=tuple(events),
            principal=principal,
            approximate=bool(unknown),
            unknown_rules=unknown,
            unlogged=unlogged,
        )
    return Exhausted(candidate.id)
