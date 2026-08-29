"""Running the DSL's ``check`` blocks — questions a rule set is asked, answered with proofs.

A check is a named question about the loaded rules (and, for most types, the account).  Each
type answers one question and ``pass`` means the defender's property holds:

======================  ==========================================================  ==============
type                    question                                                    pass means
======================  ==========================================================  ==============
``coverage``            is every reachable+logged event for ``permission`` /        no gap (proof)
                        ``permissions like`` / ``scope`` — optionally only those
                        matching ``event`` — observed by some rule?
``candidate``           is the technique ``for X`` caught however it is scheduled?  always detected
``compare``             do rules ``left A`` and ``right B`` observe the same        equivalent
                        events?
``dead_rules``          can every rule in ``rules [...]`` (default: all             none dead
                        single-event rules) fire on some reachable+logged event?
``redundant_rules``     is every rule in ``rules [...]`` needed, i.e. does it        none redundant
                        observe an event no other rule observes?
``boundary``            can any event matching ``event`` — except those matching     none slips
                        ``allowed`` — happen unseen?  ``mode fires_single``
                        (default) = a rule fires on it; ``mode observed`` = any
                        rule's event pattern (correlation rules too) accepts it
``require_coverage``    is step ``step S`` of technique ``for X`` (its method and    step watched
                        ``where`` payload) observed however it is realized?
``attempt_coverage``    same, for a *denied* attempt (``granted = false``)          attempt watched
``public_access``       can an anonymous principal (``allUsers`` /                  none unseen
                        ``allAuthenticatedUsers``) use ``permission`` on a
                        resource matching ``resource like`` unseen?
======================  ==========================================================  ==============

Verdicts are three-valued (``pass`` / ``fail`` / ``unknown``) and every witness is replayed
through the concrete oracle before it is believed; a proof that leaned on an approximate rule
is flagged ``approximate``.  ``rules [...]`` restricts the library the check sees.  What has no
engine (``mode fires_bg``) answers ``unknown`` rather than guess (Invariant #1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Literal

import z3

from decnique.detections import DetectionLibrary
from decnique.dsl.ast import Bundle, Check, Detection
from decnique.env.model import Account
from decnique.eval import fires
from decnique.model.predicates import Cmp, Like, referenced_fields
from decnique.smt.coverage import CoverageContext, Gap, NoGap, find_gap
from decnique.smt.stealth import AlwaysDetected, Evasive, NotFeasible, stealth_feasible

Verdict = Literal["pass", "fail", "unknown"]

IMPLEMENTED: tuple[str, ...] = (
    "coverage", "candidate", "compare", "dead_rules", "redundant_rules",
    "boundary", "require_coverage", "attempt_coverage", "public_access",
)
ANONYMOUS: tuple[str, ...] = ("allUsers", "allAuthenticatedUsers")


@dataclass(frozen=True, slots=True)
class Row:
    """One line of evidence: a permission, technique, or rule and what was proven about it."""

    label: str
    verdict: Verdict
    note: str = ""
    witness: dict | tuple[dict, ...] | None = None


@dataclass(frozen=True, slots=True)
class CheckResult:
    check: Check
    verdict: Verdict
    detail: str
    approximate: bool = False
    rows: tuple[Row, ...] = field(default_factory=tuple)

    @property
    def id(self) -> str:
        return self.check.id


class CheckError(ValueError):
    """The check is well-formed DSL but cannot be run as written (missing option, unknown id)."""


# --- helpers ----------------------------------------------------------------------------------


def _sub_lib(lib: DetectionLibrary, ids: tuple[str, ...] | None) -> DetectionLibrary:
    if not ids:
        return lib
    known = {d.id for d in lib.detections}
    missing = [i for i in ids if i not in known]
    if missing:
        raise CheckError(f"no detection named {', '.join(missing)}")
    b = lib.bundle
    return DetectionLibrary(
        Bundle(tuple(d for d in b.detections if d.id in set(ids)), b.candidates, b.checks, b.rulesets),
        lib.ref_lists,
    )


def _combine(rows: list[Row], *, approximate: bool, fail_word: str, pass_word: str) -> tuple[Verdict, str]:
    fails = [r for r in rows if r.verdict == "fail"]
    unknowns = [r for r in rows if r.verdict == "unknown"]
    if fails:
        return "fail", f"{len(fails)} of {len(rows)} {fail_word}: {', '.join(r.label for r in fails)}"
    if unknowns:
        return "unknown", f"{len(unknowns)} of {len(rows)} undecided: {', '.join(r.label for r in unknowns)}"
    if approximate:
        return "unknown", f"{pass_word}, but the proof leaned on approximate rules"
    return "pass", pass_word


def _permissions(check: Check, account: Account) -> list[str]:
    p = check.params
    if "permission" in p:
        return [str(p["permission"])]
    if "scope" in p:
        return list(p["scope"])  # type: ignore[arg-type]
    if "permissions" in p:
        pat = str(p["permissions"])
        return sorted(x for x in account.catalog.all_permissions() if fnmatchcase(x, pat))
    return sorted(x for x in account.catalog.all_permissions() if account.reachable(x))


def _event_constraint(ctx: CoverageContext, pred) -> tuple[z3.BoolRef, ...]:  # type: ignore[no-untyped-def]
    """The check's ``event`` predicate as a domain constraint: the fields it reads are present."""
    guard = [ctx.enc.ev.present(path) for _, path in referenced_fields(pred)]
    return (z3.And(ctx.enc.pred(pred), *guard) if guard else ctx.enc.pred(pred),)


def _domain_any_permission(ctx: CoverageContext, account: Account) -> tuple[z3.BoolRef, dict[str, tuple[list[str], list[str]]]]:
    """``Reach ∧ Log`` over every reachable permission of the account, as one disjunction."""
    cases: list[z3.BoolRef] = []
    per: dict[str, tuple[list[str], list[str]]] = {}
    cat = account.catalog
    for p in sorted(x for x in cat.all_permissions() if account.reachable(x)):
        logged = sorted(m for m in cat.methods_for(p) if account.logged(m))
        principals = sorted(account.principals_with(p))
        if not logged or not principals:
            continue
        per[p] = (logged, principals)
        cases.append(z3.And(*ctx.domain(p, logged, principals, account)))
    return (z3.Or(*cases) if cases else z3.BoolVal(False)), per


def _realize(ctx: CoverageContext, model: z3.ModelRef, per: dict, account: Account) -> dict | None:
    for p, (logged, principals) in per.items():
        if ctx._true(model, ctx.table.eq("permission", p)):
            event, _ = ctx.realize_event(model, p, logged, principals, account)
            return event
    return None


# --- the check types --------------------------------------------------------------------------


def _coverage(check: Check, lib: DetectionLibrary, account: Account, ctx: CoverageContext | None) -> CheckResult:
    lib = _sub_lib(lib, check.params.get("rules"))  # type: ignore[arg-type]
    ctx = ctx if ctx is not None and ctx.lib is lib else CoverageContext(lib)
    extra = _event_constraint(ctx, check.params["event"]) if "event" in check.params else ()
    rows: list[Row] = []
    approx = False
    for p in _permissions(check, account):
        res = find_gap(p, lib, account, ctx=ctx, extra=extra)
        if isinstance(res, Gap):
            approx |= res.approximate
            rows.append(Row(p, "fail", "unobserved event exists" + (" (approximate)" if res.approximate else ""), res.event))
        elif res.reason == "all_covered":
            rows.append(Row(p, "pass", "covered by " + (", ".join(res.covered_by) or "(no rule needed)")))
        elif res.reason == "exhausted":
            rows.append(Row(p, "unknown", "refinement bound exhausted"))
        else:
            rows.append(Row(p, "pass", f"vacuous: {res.reason.replace('_', ' ')}"))
    if not rows:
        return CheckResult(check, "unknown", "no permission matched", rows=())
    v, d = _combine(rows, approximate=False, fail_word="permission(s) have a blind spot", pass_word="every probed event is observed")
    return CheckResult(check, v, d, approximate=approx, rows=tuple(rows))


def _candidate(check: Check, lib: DetectionLibrary, account: Account) -> CheckResult:
    cid = check.params.get("for")
    if not cid:
        raise CheckError("candidate check needs `for <technique-id>`")
    cands = {c.id: c for c in lib.bundle.candidates}
    if cid not in cands:
        raise CheckError(f"no candidate named {cid}")
    lib = _sub_lib(lib, check.params.get("rules"))  # type: ignore[arg-type]
    res = stealth_feasible(cands[cid], lib, account)  # type: ignore[index]
    if isinstance(res, Evasive):
        note = f"{len(res.schedule)} event(s) as {res.principal} evade every rule"
        if res.unlogged:
            note += f"; not audit-logged: {', '.join(res.unlogged)} (a logging gap, not a rule gap)"
        return CheckResult(check, "fail", note, approximate=res.approximate,
                           rows=(Row(str(cid), "fail", note, res.schedule),))
    if isinstance(res, AlwaysDetected):
        return CheckResult(check, "pass", "always detected (UNSAT proof)", rows=(Row(str(cid), "pass", "always detected"),))
    if isinstance(res, NotFeasible):
        note = "vacuous: no principal can run it (" + (", ".join(res.missing) or "no one holds all permissions") + ")"
        return CheckResult(check, "pass", note, rows=(Row(str(cid), "pass", note),))
    return CheckResult(check, "unknown", "refinement bound exhausted", rows=(Row(str(cid), "unknown", "exhausted"),))


def _compare(check: Check, lib: DetectionLibrary, ctx: CoverageContext | None) -> CheckResult:
    a, b = check.params.get("left"), check.params.get("right")
    if not a or not b:
        raise CheckError("compare check needs `left <rule>` and `right <rule>`")
    ctx = ctx or CoverageContext(lib)
    by_id = {d.id: d for d in ctx.single_rules}
    for rid in (a, b):
        if rid not in {d.id for d in lib.detections}:
            raise CheckError(f"no detection named {rid}")
        if rid not in by_id:
            return CheckResult(check, "unknown", f"{rid} is a correlation rule; compare works on single-event rules")
    approx = not ({a, b} <= ctx.exact_rules)
    oa, ob = ctx._observes(by_id[a].spec), ctx._observes(by_id[b].spec)  # type: ignore[index]
    s = z3.Solver()
    s.add(*ctx.consistency)
    rows: list[Row] = []
    for label, only, other in ((f"{a} only", oa, ob), (f"{b} only", ob, oa)):
        s.push()
        s.add(only, z3.Not(other))
        sat = s.check() == z3.sat
        if sat:
            m = s.model()
            lits = [x.text for path in ctx.table.by_field for x in ctx.table.by_field[path]
                    if ctx._true(m, ctx.table.var(x))]
            rows.append(Row(label, "fail", "an event with " + (" & ".join(lits[:4]) or "no special field") + " is seen by one rule only"))
        else:
            rows.append(Row(label, "pass", "none (UNSAT)"))
        s.pop()
    fails = [r for r in rows if r.verdict == "fail"]
    if fails:
        v: Verdict = "unknown" if approx else "fail"
        return CheckResult(check, v, "the rules observe different events: " + "; ".join(r.label for r in fails),
                           approximate=approx, rows=tuple(rows))
    if approx:
        return CheckResult(check, "unknown", "equivalent over the encoding, but a rule is approximate", approximate=True, rows=tuple(rows))
    return CheckResult(check, "pass", "equivalent (both directions UNSAT)", rows=tuple(rows))


def _rule_set(check: Check, ctx: CoverageContext) -> list[Detection]:
    ids = check.params.get("rules")
    if not ids:
        return list(ctx.single_rules)
    by_id = {d.id: d for d in ctx.single_rules}
    missing = [i for i in ids if i not in by_id]  # type: ignore[union-attr]
    if missing:
        raise CheckError(f"not a single-event detection: {', '.join(missing)}")
    return [by_id[i] for i in ids]  # type: ignore[union-attr]


def _dead_rules(check: Check, lib: DetectionLibrary, account: Account, ctx: CoverageContext | None) -> CheckResult:
    ctx = ctx or CoverageContext(lib)
    dom, per = _domain_any_permission(ctx, account)
    s = z3.Solver()
    s.add(*ctx.consistency, dom)
    rows: list[Row] = []
    approx = False
    for d in _rule_set(check, ctx):
        s.push()
        s.add(ctx._observes(d.spec))
        row = Row(d.id, "unknown", "solver found a model no event realizes")
        if s.check() != z3.sat:
            exact = d.id in ctx.exact_rules
            approx |= not exact
            row = Row(d.id, "fail" if exact else "unknown", "dead: no reachable+logged event fires it" + ("" if exact else " (approximate rule)"))
        else:
            event = _realize(ctx, s.model(), per, account)
            if event is not None:
                v = fires(d.spec, [event], ref_lists=lib.ref_lists)
                if v is True:
                    row = Row(d.id, "pass", f"fires on {event.get('method', '?')} by {event.get('principal', '?')}", event)
                elif v is None:
                    row = Row(d.id, "unknown", "the witness leaves the rule undecided")
        s.pop()
        rows.append(row)
    if not rows:
        return CheckResult(check, "unknown", "no single-event rule to test")
    v, det = _combine(rows, approximate=approx, fail_word="rule(s) are dead", pass_word="every rule can fire")
    return CheckResult(check, v, det, approximate=approx, rows=tuple(rows))


def _redundant_rules(check: Check, lib: DetectionLibrary, account: Account, ctx: CoverageContext | None) -> CheckResult:
    ctx = ctx or CoverageContext(lib)
    dom, per = _domain_any_permission(ctx, account)
    obs = {d.id: ctx._observes(d.spec) for d in ctx.single_rules}
    s = z3.Solver()
    s.add(*ctx.consistency, dom)
    rows: list[Row] = []
    approx = False
    for d in _rule_set(check, ctx):
        others = [o for rid, o in obs.items() if rid != d.id]
        s.push()
        s.add(obs[d.id], z3.Not(z3.Or(*others)) if others else z3.BoolVal(True))
        row = Row(d.id, "unknown", "solver found a model no event realizes")
        if s.check() != z3.sat:
            inv = {d.id, *(rid for rid in obs if rid != d.id)}
            exact = inv <= ctx.exact_rules
            approx |= not exact
            row = Row(d.id, "fail", "redundant: every event it observes trips another rule" + ("" if exact else " (approximate)"))
        else:
            event = _realize(ctx, s.model(), per, account)
            if event is not None:
                vs = {r.id: fires(r.spec, [event], ref_lists=lib.ref_lists) for r in ctx.single_rules}
                if vs[d.id] is True and not any(v is True for rid, v in vs.items() if rid != d.id):
                    unk = [rid for rid, v in vs.items() if v is None and rid != d.id]
                    approx |= bool(unk)
                    row = Row(d.id, "pass", f"alone on {event.get('method', '?')}" + (f" (undecided: {', '.join(unk)})" if unk else ""), event)
        s.pop()
        rows.append(row)
    if not rows:
        return CheckResult(check, "unknown", "no single-event rule to test")
    v, det = _combine(rows, approximate=approx, fail_word="rule(s) are redundant", pass_word="every rule observes something on its own")
    return CheckResult(check, v, det, approximate=approx, rows=tuple(rows))


def _gap_row(label: str, res, *, note_pass: str = "covered") -> Row:  # type: ignore[no-untyped-def]
    if isinstance(res, Gap):
        return Row(label, "fail", "unobserved event exists" + (" (approximate)" if res.approximate else ""), res.event)
    if res.reason == "all_covered":
        return Row(label, "pass", f"{note_pass} by " + (", ".join(res.covered_by) or "(no rule needed)"))
    if res.reason == "exhausted":
        return Row(label, "unknown", "refinement bound exhausted")
    return Row(label, "pass", f"vacuous: {res.reason.replace('_', ' ')}")


def _boundary(check: Check, lib: DetectionLibrary, account: Account, ctx: CoverageContext | None) -> CheckResult:
    p = check.params
    if "event" not in p:
        raise CheckError("boundary check needs `event <expr>` (the class of events that must be seen)")
    mode = str(p.get("mode", "fires_single"))
    if mode == "fires_bg":
        return CheckResult(check, "unknown", "mode fires_bg (against a background trace) has no engine yet")
    lib = _sub_lib(lib, p.get("rules"))  # type: ignore[arg-type]
    ctx = ctx if ctx is not None and ctx.lib is lib else CoverageContext(lib)
    extra = list(_event_constraint(ctx, p["event"]))
    if "allowed" in p:
        extra.append(z3.Not(_event_constraint(ctx, p["allowed"])[0]))
    # `observed`: an event is seen when ANY rule's event pattern accepts it — correlation rules
    # included — so their patterns join the solver's Observes, and replay uses `observes`.
    pushed = mode == "observed"
    if pushed:
        ctx.solver.push()
        for d in lib.detections:
            if d.id in ctx.tracks:
                continue
            for ev in d.spec.events:
                body = ctx.enc.pred(ev.pred)
                guard = [ctx.enc.ev.present(path) for _, path in referenced_fields(ev.pred)]
                ctx.solver.add(z3.Not(z3.And(body, *guard) if guard else body))
    rows: list[Row] = []
    approx = False
    try:
        for perm in _permissions(check, account):
            res = find_gap(perm, lib, account, ctx=ctx, extra=tuple(extra))
            if isinstance(res, Gap) and pushed:
                obs = lib.observing(res.event)
                if obs.observed:  # the solver's view was approximate; do not believe it
                    rows.append(Row(perm, "unknown", "witness rejected by replay (approximate rule)"))
                    continue
                res = Gap(res.permission, res.event, res.approximate or obs.approximate,
                          res.unknown_rules + obs.unknown, res.caveats)
            if isinstance(res, Gap):
                approx |= res.approximate
                rows.append(_gap_row(perm, res))
                break  # one slip is enough to fail the boundary
            if res.reason == "all_covered":
                rows.append(Row(perm, "pass", "held by " + (", ".join(res.covered_by) or "(no rule needed)")))
            elif res.reason == "exhausted":
                rows.append(Row(perm, "unknown", "refinement bound exhausted"))
    finally:
        if pushed:
            ctx.solver.pop()
    if not rows:
        return CheckResult(check, "pass", "vacuous: no reachable+logged permission in scope", rows=())
    v, d = _combine(rows, approximate=False, fail_word="permission(s) let a matching event slip", pass_word=f"no matching event slips ({mode})")
    return CheckResult(check, v, d, approximate=approx, rows=tuple(rows))


def _step_coverage(check: Check, lib: DetectionLibrary, account: Account, ctx: CoverageContext | None, *, granted: bool) -> CheckResult:
    cid = check.params.get("for")
    if not cid:
        raise CheckError(f"{check.type} check needs `for <technique-id>` (and optionally `step <name>`)")
    cands = {c.id: c for c in lib.bundle.candidates}
    if cid not in cands:
        raise CheckError(f"no candidate named {cid}")
    cand = cands[cid]  # type: ignore[index]
    steps = [st for st in cand.footprint.steps if "step" not in check.params or st.id == check.params["step"]]
    if not steps:
        raise CheckError(f"{cid} has no step named {check.params.get('step')}")
    lib = _sub_lib(lib, check.params.get("rules"))  # type: ignore[arg-type]
    ctx = ctx if ctx is not None and ctx.lib is lib else CoverageContext(lib)
    cat = account.catalog
    rows: list[Row] = []
    approx = False
    for st in steps:
        label = f"{cid}.{st.id}"
        perms = [rq.permission for rq in cand.required if st.method in cat.methods_for(rq.permission)]
        if not perms:
            rows.append(Row(label, "unknown", f"catalog does not tie {st.method} to any required permission"))
            continue
        if not account.logged(st.method):
            rows.append(Row(label, "pass", f"vacuous: {st.method} is not audit-logged here"))
            continue
        extra = [ctx.table.eq("method", st.method)]
        if st.where is not None:
            extra.extend(_event_constraint(ctx, st.where))
        # the step is watched only if it is watched under EVERY permission it may run under
        row = Row(label, "pass", "vacuous: no principal holds the permission")
        for perm in perms:
            row = _gap_row(label, find_gap(perm, lib, account, ctx=ctx, extra=tuple(extra), granted=granted), note_pass="watched")
            if row.verdict != "pass":
                break
        approx |= isinstance(row.witness, dict) and "(approximate)" in row.note
        rows.append(row)
    what = "denied attempt" if not granted else "step"
    v, d = _combine(rows, approximate=False, fail_word=f"{what}(s) can happen unseen", pass_word=f"every {what} is watched")
    return CheckResult(check, v, d, approximate=approx, rows=tuple(rows))


def _public_access(check: Check, lib: DetectionLibrary, account: Account, ctx: CoverageContext | None) -> CheckResult:
    lib = _sub_lib(lib, check.params.get("rules"))  # type: ignore[arg-type]
    ctx = ctx if ctx is not None and ctx.lib is lib else CoverageContext(lib)
    anon = [a for a in ANONYMOUS if a in account.bindings]
    if not anon:
        return CheckResult(check, "pass", "vacuous: the account grants nothing to allUsers / allAuthenticatedUsers")
    want = str(check.params["resource"]) if "resource" in check.params else None
    rows: list[Row] = []
    approx = False
    if any(k in check.params for k in ("permission", "permissions", "scope")):
        perms = _permissions(check, account)
    else:  # default: whatever the anonymous grants hold, on their own resources
        perms = sorted(p for p in account.catalog.all_permissions()
                       if any(account.reach(a, p, g.resource) for a in anon for g in account.bindings[a]))
    for perm in perms:
        for a in anon:
            # ask per anonymous grant, on that grant's own resource (a project-scoped grant does
            # not reach `*`); the witness must carry a resource inside the grant AND the glob
            for g in account.bindings[a]:
                if not account.reach(a, perm, g.resource):
                    continue
                if want and not (fnmatchcase(g.resource, want) or "*" in g.resource):
                    continue  # the grant's resource cannot match the asked glob
                res_pred = (Like(field=(None, "resource"), pattern=g.resource) if "*" in g.resource
                            else Cmp(field=(None, "resource"), op="=", value=g.resource))
                extra = _event_constraint(ctx, res_pred)
                if want:
                    extra += _event_constraint(ctx, Like(field=(None, "resource"), pattern=want))
                r = find_gap(perm, lib, account, ctx=ctx, extra=extra, principals=(a,), resource=g.resource)
                row = _gap_row(f"{perm} as {a} on {g.resource}", r)
                approx |= isinstance(r, Gap) and r.approximate
                rows.append(row)
    if not rows:
        return CheckResult(check, "pass", "vacuous: no permission in scope is granted to anonymous principals on a matching resource")
    v, d = _combine(rows, approximate=False, fail_word="anonymous use(s) go unseen", pass_word="every anonymous use is observed")
    return CheckResult(check, v, d, approximate=approx, rows=tuple(rows))


# --- entry points -----------------------------------------------------------------------------


def run_check(
    check: Check,
    lib: DetectionLibrary,
    account: Account | None = None,
    *,
    ctx: CoverageContext | None = None,
) -> CheckResult:
    """Answer one check.  Never raises on a sound-but-undecidable question; raises
    :class:`CheckError` only when the block cannot be run as written."""
    if check.type not in IMPLEMENTED:
        return CheckResult(check, "unknown", f"check type {check.type!r} has no engine yet")
    if check.type == "compare":
        return _compare(check, lib, ctx)
    if account is None:
        raise CheckError(f"{check.type} check needs an account (Reach / Log)")
    if check.type == "coverage":
        return _coverage(check, lib, account, ctx)
    if check.type == "candidate":
        return _candidate(check, lib, account)
    if check.type == "dead_rules":
        return _dead_rules(check, lib, account, ctx)
    if check.type == "redundant_rules":
        return _redundant_rules(check, lib, account, ctx)
    if check.type == "boundary":
        return _boundary(check, lib, account, ctx)
    if check.type == "public_access":
        return _public_access(check, lib, account, ctx)
    return _step_coverage(check, lib, account, ctx, granted=(check.type == "require_coverage"))


def run_checks(
    checks: tuple[Check, ...] | list[Check],
    lib: DetectionLibrary,
    account: Account | None = None,
) -> list[CheckResult]:
    ctx = CoverageContext(lib) if checks else None  # encode the rules once for the whole batch
    return [run_check(c, lib, account, ctx=ctx) for c in checks]
