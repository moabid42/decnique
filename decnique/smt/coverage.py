"""Single-event coverage — ``Reach ∧ Log ∧ ¬⋁Observes`` over the atom abstraction.

See ``docs/COVERAGE_ABSTRACTION.md``.  Every string field is abstracted to the finite set of
atomic tests the rules make on it (:mod:`decnique.smt.atoms`), so the query is propositional
(plus exact bit-vector / integer theories for ``ip`` / ``int``); z3's string theory is not used.

* :class:`CoverageContext` encodes every single-event rule **once per library**; a permission
  only adds its small domain (logged methods, allowed principals, the permission itself, the
  method→field invariants) under ``push``/``pop``.
* Every model is *realized* to a concrete event and replayed through the concrete oracle
  (:func:`decnique.eval.fires`) and the account (``reach`` / ``logged``).  A proposal a rule
  fires on is blocked and the search refines, so a returned :class:`Gap` is sound by
  construction (Invariant #3).  Atom consistency the solver did not know about is learned as
  proven clauses (CEGAR); an UNSAT reached only through proven clauses is a proof
  (``all_covered``), otherwise the result is the honest ``exhausted``.
* Honesty (Invariant #1): a detection that answers *don't know* on the witness makes the gap
  ``approximate``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import z3

from decnique.detections import DetectionLibrary
from decnique.env.model import Account
from decnique.eval import fires
from decnique.model import event_fields as ef
from decnique.model.predicates import referenced_fields
from decnique.smt.atoms import Atom, AtomEncoder, AtomTable, Realizer, is_string_sort

ENUMERATED = ("method", "principal", "permission")  # fixed by the permission's domain


@dataclass(frozen=True, slots=True)
class Gap:
    """A concrete, replay-verified blind-spot event for one permission."""

    permission: str
    event: dict
    approximate: bool
    unknown_rules: tuple[str, ...] = ()
    caveats: tuple[str, ...] = ()  # model-side reasons the witness is only approximate

    @property
    def found(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class NoGap:
    """No blind spot for this permission (or none within the refinement bound)."""

    permission: str
    reason: str  # unreachable | no_logged_method | all_covered | exhausted
    covered_by: tuple[str, ...] = ()  # rule ids in the UNSAT core: together they cover it

    @property
    def found(self) -> bool:
        return False


GapResult = Gap | NoGap


def _fires_on_one_event(spec) -> bool:  # type: ignore[no-untyped-def]
    """True when a *single* matching event makes the rule fire — one event variable and a count
    condition met by one occurrence (``#v >= 1`` and the like).  Such rules constrain
    single-event coverage exactly, so folding them into ``Observes`` lets the search *prove* a
    permission covered.  ``>= N (N>1)`` or value-aggregate conditions need several events and
    are left to concrete replay."""
    from decnique.model.trace import Count, CTrue

    if len(spec.events) != 1:
        return False
    c = spec.condition
    if isinstance(c, CTrue):
        return True
    if isinstance(c, Count) and c.var == spec.events[0].name:
        return _count_true(c.op, 1, c.n) and not _count_true(c.op, 0, c.n)
    return False


def _count_true(op: str, x: int, n: int) -> bool:
    return {
        ">=": x >= n, ">": x > n, "<=": x <= n, "<": x < n, "==": x == n, "=": x == n,
        "!=": x != n,
    }.get(op, False)


def _probe_paths(lib: DetectionLibrary) -> tuple[str, ...]:
    """Every field the witness must carry: the closed vocabulary plus any ``udm:``/``tags.``
    leaf a rule reads, so concrete replay sees a faithful, complete event."""
    paths = set(ef.FIELD_NAMES)
    for d in lib.detections:
        for e in d.spec.events:
            for _, p in referenced_fields(e.pred):
                paths.add(p)
    return tuple(sorted(paths))


class CoverageContext:
    """The library-wide part of the coverage problem, built once and shared by all permissions."""

    #: above this many atoms the MaxSAT witness minimization is skipped (plain SAT models)
    MINIMIZE_UP_TO = 5000

    def __init__(self, lib: DetectionLibrary, *, minimize: bool | None = None) -> None:
        self.lib = lib
        self.table = AtomTable()
        self.enc = AtomEncoder(self.table)
        self.realizer = Realizer(self.table)
        self.paths = _probe_paths(lib)
        self.single_rules = [d for d in lib.detections if _fires_on_one_event(d.spec)]
        obs = []
        self.exact_rules: set[str] = set()  # rules whose encoding used no approximate atom
        for d in self.single_rules:
            n = len(self.enc.approx)
            obs.append(self._observes(d.spec))
            if len(self.enc.approx) == n:
                self.exact_rules.add(d.id)
        # each rule's ¬Observes is asserted under its own assumption literal, so an UNSAT core
        # names the rules that jointly cover a permission ("caught by …")
        self.tracks = {d.id: z3.Bool(f"rule.{d.id}") for d in self.single_rules}
        self.any_obs = z3.Or(*obs) if obs else z3.BoolVal(False)
        exact = [o for d, o in zip(self.single_rules, obs) if d.id in self.exact_rules]
        self.any_obs_exact = z3.Or(*exact) if exact else z3.BoolVal(False)
        self.consistency: list[z3.BoolRef] = []
        if minimize is None:
            minimize = len(self.table.vars) <= self.MINIMIZE_UP_TO
        self.minimize = minimize
        # MaxSAT: prefer every presence bit false (always — an optional field the rules do not
        # force should stay absent), and every atom false when the table is small enough.
        # Witnesses then satisfy only what the rules force, which keeps them small, readable
        # ("an event whose user_agent does not contain X") and realizable.
        self.solver = z3.Optimize()
        self.solver.set("random_seed", 0)  # reproducible witnesses
        for d, o in zip(self.single_rules, obs):
            self.solver.add(z3.Implies(self.tracks[d.id], z3.Not(o)))
        for path in list(self.table.by_field):
            if path not in ENUMERATED:
                for c in self.table.eq_exclusion(path):
                    self.solver.add(c)
                    self.consistency.append(c)
        for b in self.enc.ev._present.values():
            self.solver.add_soft(z3.Not(b), weight=2)
        if minimize:
            for v in self.table.vars.values():
                self.solver.add_soft(z3.Not(v))
        # A rule that already fires on the *empty* trace (e.g. ``#e < 5`` holds at zero events)
        # fires regardless of the event, so it observes nothing; replaying it would "cover"
        # every permission.  Such rules are excluded from replay and listed here.
        self.vacuous = tuple(
            d.id for d in lib.detections if fires(d.spec, [], ref_lists=lib.ref_lists) is True
        )
        self.replay_rules = [d for d in lib.detections if d.id not in set(self.vacuous)]
        self.learned: list[z3.BoolRef] = []
        self.stats = {"checks": 0, "learned": 0, "blocked": 0, "unproven": 0}

    def _observes(self, spec) -> z3.BoolRef:  # type: ignore[no-untyped-def]
        """Single-event ``Observes`` under the zero-value guard."""
        var = spec.events[0]
        body = self.enc.pred(var.pred)
        if spec.options.allow_zero_values:
            return body
        guard = [self.enc.ev.present(path) for _, path in referenced_fields(var.pred)]
        return z3.And(body, *guard) if guard else body

    # -- domain ------------------------------------------------------------------------------

    def _determine(self, path: str, value: str) -> list[z3.BoolRef]:
        """Every atom on ``path`` takes the truth value it has on the constant ``value``."""
        out = []
        for a in self.table.by_field.get(path, ()):
            h = a.holds(value)
            if h is not None:
                out.append(self.table.var(a) if h else z3.Not(self.table.var(a)))
        return out

    def domain(
        self, permission: str, methods: list[str], principals: list[str], account: Account,
        *, granted: bool = True,
    ) -> list[z3.BoolRef]:
        ev, t = self.enc.ev, self.table
        out: list[z3.BoolRef] = []
        for path, values in (("method", methods), ("principal", principals)):
            sel = [t.eq(path, v) for v in values]
            out.append(z3.Or(*sel))
            if len(sel) > 1:
                out.append(z3.AtMost(*sel, 1))
            for v in values:  # the chosen value decides every other atom on the field
                out.append(z3.Implies(t.eq(path, v), z3.And(*self._determine(path, v))))
        out.append(ev.present("principal"))
        out.append(t.eq("permission", permission))
        out.extend(self._determine("permission", permission))
        for m in methods:  # realism invariants: a real event fixes some fields by its method
            for path, value in account.catalog.field_invariants(m).items():
                if is_string_sort(path):
                    out.append(z3.Implies(t.eq("method", m), z3.And(*self._determine(path, value))))
            for path in account.catalog.required_fields(m):  # ... and always carries others
                out.append(z3.Implies(t.eq("method", m), ev.present(path)))
        out.append(ev.term("granted") == z3.BoolVal(granted))  # False = a denied attempt
        return out

    # -- decoding ------------------------------------------------------------------------------

    def _true(self, model: z3.ModelRef, b: z3.BoolRef) -> bool:
        return z3.is_true(model.eval(b, model_completion=True))

    def _present(self, model: z3.ModelRef, path: str) -> bool:
        return self._true(model, self.enc.ev.present(path))

    def _chosen(self, model: z3.ModelRef, path: str, values: list[str]) -> str:
        for v in values:
            if self._true(model, self.table.eq(path, v)):
                return v
        return values[0]

    def realize_event(
        self, model: z3.ModelRef, permission: str, methods: list[str], principals: list[str],
        account: Account, *, granted: bool = True,
    ) -> tuple[dict | None, list[z3.BoolRef]]:
        """Decode a model into a concrete event, or ``(None, learned)`` when some field cannot be
        realized — ``learned`` then holds the proven clauses explaining it (possibly none)."""
        m = self._chosen(model, "method", methods)
        event: dict = {
            "method": m,
            "principal": self._chosen(model, "principal", principals),
            "permission": permission,
            "granted": granted,
        }
        event.update(account.catalog.field_invariants(m))
        required = account.catalog.required_fields(m)  # carried even if no rule reads them
        for path in (*self.paths, *(p for p in required if p not in self.paths)):
            if path in event or path in ENUMERATED:
                continue
            if not self._present(model, path):
                continue
            if is_string_sort(path):
                atoms = self.table.by_field.get(path, [])
                true = [a for a in atoms if self._true(model, self.table.var(a))]
                tset = set(true)
                false = [a for a in atoms if a not in tset]
                examples = account.catalog.example_values(path, principal=event["principal"])
                r = self.realizer.realize(true, false, examples)
                if not r.ok:
                    return None, list(r.learned)
                _put(event, path, r.value)
            else:
                _put(event, path, self._decode_term(model, path))
        return event, []

    def _decode_term(self, model: z3.ModelRef, path: str):  # -> value
        ev = self.enc.ev
        v = model.eval(ev.term(path), model_completion=True)
        sort = ev.sort_of(path)
        if sort in ("int", "time"):
            return v.as_long()
        if sort == "bool":
            return z3.is_true(v)
        if sort == "ip":
            return str(ipaddress.IPv4Address(v.as_long() & 0xFFFFFFFF))
        return v.as_string()

    def block(self, model: z3.ModelRef) -> z3.BoolRef:
        """Exclude exactly the assignments that realize this model's event: presence bits, the
        atoms of every present field, and the non-string terms.  Approximate atoms are
        irrelevant to the event, so they are left out."""
        ev = self.enc.ev
        diffs: list[z3.BoolRef] = []
        for path, pres in ev._present.items():
            diffs.append(z3.Not(pres) if self._true(model, pres) else pres)
        for path, atoms in self.table.by_field.items():
            if not self._present(model, path):
                continue
            for a in atoms:
                b = self.table.var(a)
                diffs.append(z3.Not(b) if self._true(model, b) else b)
        for path, term in ev._terms.items():
            if is_string_sort(path) or not self._present(model, path):
                continue
            diffs.append(term != model.eval(term, model_completion=True))
        return z3.Or(*diffs) if diffs else z3.BoolVal(False)


def _put(event: dict, path: str, value) -> None:  # type: ignore[no-untyped-def]
    """Store a witness value where the concrete oracle reads it."""
    if ef.is_udm(path):
        event.setdefault("udm", {})[ef.udm_path(path)] = value
    elif path.startswith(ef.TAG_PREFIX):
        event.setdefault("tags", {})[path[len(ef.TAG_PREFIX):]] = value
    else:
        event[path] = value


def find_gap(
    permission: str,
    lib: DetectionLibrary,
    account: Account,
    *,
    max_refine: int = 64,
    ctx: CoverageContext | None = None,
    extra: tuple[z3.BoolRef, ...] = (),
    principals: tuple[str, ...] | None = None,
    granted: bool = True,
    resource: str = "*",
) -> GapResult:
    """Solve ``Reach ∧ Log ∧ ¬⋁Observes`` for one permission; return a verified witness.
    ``extra`` adds constraints to the domain (used to ask "is there a gap *with* this atom?");
    ``principals`` restricts the actor (e.g. to ``allUsers``); ``granted=False`` asks about
    *denied* attempts instead of successful calls; ``resource`` is the resource ``Reach`` is
    asked about (a grant scoped to a project reaches it, not ``*``)."""
    cat = account.catalog
    if not account.reachable(permission, resource):
        return NoGap(permission, "unreachable")
    logged = sorted(m for m in cat.methods_for(permission) if account.logged(m))
    if not logged:
        return NoGap(permission, "no_logged_method")
    # A method name the catalog cannot confirm in real audit logs must not be the *reason* a
    # gap exists: it would let the solver dodge every rule that names the real method.  Search
    # over confirmed names when there are any; fall back to unverified ones (with a caveat).
    verified = [m for m in logged if cat.verified(m)]
    logged = verified or logged
    holders = account.principals_with(permission, resource)
    principals = sorted(p for p in holders if principals is None or p in principals)
    if not principals:
        return NoGap(permission, "unreachable")

    ctx = ctx or CoverageContext(lib)
    s = ctx.solver
    learned_here: list[z3.BoolRef] = []
    unproven = False
    s.push()
    try:
        for c in ctx.domain(permission, logged, principals, account, granted=granted):
            s.add(c)
        for c in extra:
            s.add(c)
        for m in logged:  # prefer a witness on a method confirmed to appear in audit logs
            if not cat.verified(m):
                s.add_soft(z3.Not(ctx.table.eq("method", m)), weight=100)
        for _ in range(max_refine):
            ctx.stats["checks"] += 1
            if s.check(*ctx.tracks.values()) != z3.sat:
                core = tuple(sorted(str(b)[5:] for b in s.unsat_core()))  # strip "rule."
                return NoGap(permission, "exhausted" if unproven else "all_covered", core)
            model = s.model()
            event, learned = ctx.realize_event(model, permission, logged, principals, account,
                                               granted=granted)
            if learned:
                ctx.stats["learned"] += len(learned)
                learned_here.extend(learned)
                for c in learned:
                    s.add(c)
            if event is None:
                if not learned:  # nothing provable → block this assignment, lose the proof
                    unproven = True
                    ctx.stats["unproven"] += 1
                    s.add(ctx.block(model))
                continue
            principal = event["principal"]
            if not account.logged(event["method"]) or not account.reach(
                principal, permission, event.get("resource", resource)
            ):
                ctx.stats["blocked"] += 1
                s.add(ctx.block(model))
                continue
            # The concrete oracle is authoritative: does ANY rule fire / is any uncertain?
            verdicts = {
                d.id: fires(d.spec, [event], ref_lists=lib.ref_lists) for d in ctx.replay_rules
            }
            if any(v is True for v in verdicts.values()):
                ctx.stats["blocked"] += 1
                s.add(ctx.block(model))
                continue
            unknown_rules = tuple(rid for rid, v in verdicts.items() if v is None)
            caveats: tuple[str, ...] = ()
            if not cat.verified(event["method"]):
                caveats += (
                    f"method {event['method']} is not confirmed to appear in audit logs "
                    "(catalog entry unverified)",
                )
            return Gap(
                permission=permission,
                event=event,
                approximate=bool(unknown_rules) or bool(caveats),
                unknown_rules=unknown_rules,
                caveats=caveats,
            )
        return NoGap(permission, "exhausted")
    finally:
        s.pop()
        for c in learned_here:  # proven clauses survive the pop: they are library facts
            s.add(c)
        ctx.learned.extend(learned_here)


@dataclass(frozen=True, slots=True)
class CoverageReport:
    gaps: tuple[Gap, ...]
    covered: tuple[str, ...]
    unreachable: tuple[str, ...]
    unlogged: tuple[str, ...]
    approximate: tuple[str, ...]
    exhausted: tuple[str, ...] = ()

    def summary(self) -> dict:
        return {
            "permissions_probed": len(self.gaps)
            + len(self.covered)
            + len(self.unreachable)
            + len(self.unlogged),
            "gaps": len(self.gaps),
            "approximate": len(self.approximate),
            "covered": len(self.covered),
            "exhausted": len(self.exhausted),
            "unreachable": len(self.unreachable),
            "unlogged": len(self.unlogged),
        }


def probe_permissions(
    lib: DetectionLibrary,
    account: Account,
    permissions: tuple[str, ...] | None = None,
    *,
    ctx: CoverageContext | None = None,
) -> CoverageReport:
    """Probe a set of permissions (default: every catalog permission the account can reach),
    sharing one :class:`CoverageContext` so the rules are encoded once."""
    if permissions is None:
        permissions = tuple(
            sorted(p for p in account.catalog.all_permissions() if account.reachable(p))
        )
    ctx = ctx or CoverageContext(lib)
    gaps: list[Gap] = []
    covered: list[str] = []
    unreachable: list[str] = []
    unlogged: list[str] = []
    approximate: list[str] = []
    exhausted: list[str] = []
    for p in permissions:
        r = find_gap(p, lib, account, ctx=ctx)
        if isinstance(r, Gap):
            gaps.append(r)
            if r.approximate:
                approximate.append(p)
        elif r.reason == "unreachable":
            unreachable.append(p)
        elif r.reason == "no_logged_method":
            unlogged.append(p)
        else:
            covered.append(p)  # all_covered, or exhausted (inconclusive; listed separately too)
            if r.reason == "exhausted":
                exhausted.append(p)
    return CoverageReport(
        gaps=tuple(gaps),
        covered=tuple(covered),
        unreachable=tuple(unreachable),
        unlogged=tuple(unlogged),
        approximate=tuple(approximate),
        exhausted=tuple(exhausted),
    )


def describe_atom(a: Atom) -> str:
    f = a.field
    if f.startswith("udm:"):
        f = f[4:].replace("target.resource.attribute.labels[", "labels[")
    op = {"eq": "=", "contains": "contains", "startswith": "startswith", "endswith": "endswith",
          "glob": "like", "regex": "matches"}[a.kind]
    return f'{f} {op} "{a.text}"' + (" nocase" if a.nocase else "")


@dataclass(frozen=True, slots=True)
class AtomVerdict:
    """Coverage of a change — one or two atomic tests held together — on this permission's
    events: is there an unobserved event on which they hold?"""

    atoms: tuple[Atom, ...]
    result: GapResult

    @property
    def covered(self) -> bool:
        return isinstance(self.result, NoGap) and self.result.reason == "all_covered"

    def describe(self) -> str:
        return "  ∧  ".join(describe_atom(a) for a in self.atoms)


def probe_atoms(
    permission: str,
    lib: DetectionLibrary,
    account: Account,
    *,
    ctx: CoverageContext | None = None,
    max_atoms: int = 40,
) -> tuple[AtomVerdict, ...]:
    """The blind *region* of a permission, one atom at a time: for every atomic test the rules
    make on the fields a real event of this permission carries (its binding deltas, user agent,
    …), ask whether an unobserved event exists **on which that test holds**.  "covered" atoms
    are the changes the corpus watches; "gap" atoms are the changes it does not.  Answers the
    question ``blindspots`` alone cannot: not *whether* there is a hole, but *which* changes
    fall into it."""
    from decnique.dsl.interpret import spec_methods_literal

    ctx = ctx or CoverageContext(lib)
    cat = account.catalog
    logged = sorted(m for m in cat.methods_for(permission) if account.logged(m))
    if not logged or not account.reachable(permission):
        return ()
    fields: set[str] = set()
    for m in logged:
        fields.update(cat.required_fields(m))
    for d in lib.detections:  # fields read by rules that name one of this permission's methods
        lits = spec_methods_literal(d.spec)
        if lits and not lits.isdisjoint(logged):
            for e in d.spec.events:
                for _, pth in referenced_fields(e.pred):
                    fields.add(pth)
    skip = set(ENUMERATED) | {"service", "product_name", "event_type", "granted"}
    atoms = [
        a for f in sorted(fields) if f not in skip
        for a in ctx.table.by_field.get(f, ())
    ]
    seen: set[tuple[str, str, str, bool]] = set()
    picked: list[Atom] = []
    for a in atoms:
        key = (a.field, a.kind, a.text.lower(), a.nocase)
        if key not in seen:
            seen.add(key)
            picked.append(a)
    # What is watched is usually a *combination* (ADD ∧ owner ∧ serviceAccount), so besides
    # each atom alone, probe combinations over the required fields: one atom per field, always
    # including the first required field (the delta *action*) so "grant" and "revoke" are never
    # lumped together.
    required_order = [f for m in logged for f in cat.required_fields(m)]
    required = list(dict.fromkeys(required_order))
    combos: list[tuple[Atom, ...]] = [(a,) for a in picked[:max_atoms]]
    by_req: dict[str, list[Atom]] = {f: [a for a in picked if a.field == f] for f in required}
    if required and by_req[required[0]]:
        import itertools

        head = required[0]
        rest = [f for f in required[1:] if by_req[f]]
        for k in range(1, len(rest) + 1):
            for fields_k in itertools.combinations(rest, k):
                for tail in itertools.product(*[by_req[f] for f in fields_k]):
                    for a in by_req[head]:
                        combos.append((a, *tail))
    out = []
    for atoms in combos[: max_atoms * 3]:
        r = find_gap(permission, lib, account, ctx=ctx, extra=tuple(ctx.table.var(a) for a in atoms))
        out.append(AtomVerdict(atoms, r))
    return tuple(out)


# --- explaining a change: which rules catch it, which conditions it dodges -------------------


def dodged_conditions(lib: DetectionLibrary, event: dict, rule_ids: tuple[str, ...], *, limit: int = 3) -> dict[str, list[str]]:
    """For each rule, the leaves of its predicate that are *false* on ``event`` — the conditions
    the event dodges.  Rule ids come from the caller (e.g. the rules naming the method)."""
    from decnique.dsl.format import pred as fmt
    from decnique.dsl.interpret import evaluate
    from decnique.model.predicates import LEAF_TYPES, All, Any, Not

    def leaves(p):  # type: ignore[no-untyped-def]
        if isinstance(p, (All, Any)):
            return [x for c in p.children for x in leaves(c)]
        if isinstance(p, Not):
            return [p]
        return [p] if isinstance(p, LEAF_TYPES) else []

    out: dict[str, list[str]] = {}
    for rid in rule_ids:
        d = lib.get(rid)
        failed = []
        for var in d.spec.events:
            for leaf in leaves(var.pred):
                if evaluate(leaf, event, ref_lists=lib.ref_lists) is False:
                    failed.append(fmt(leaf))
        out[rid] = failed[:limit] + (["…"] if len(failed) > limit else [])
    return out


def rules_naming(lib: DetectionLibrary, methods: list[str]) -> tuple[str, ...]:
    """Rules whose literal method tests include one of ``methods``."""
    from decnique.dsl.interpret import spec_methods_literal

    out = []
    for d in lib.detections:
        lits = spec_methods_literal(d.spec)
        if lits and not lits.isdisjoint(methods):
            out.append(d.id)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class Cube:
    """One implicant of the blind region: every event satisfying these literals (within the
    permission's domain) is observed by no exactly-encoded rule."""

    literals: tuple[tuple[str, bool], ...]  # (description, polarity)
    proven: bool  # False: minimisation hit the bound; the cube may include observed events

    def describe(self) -> str:
        return "  ∧  ".join(d if pos else f"¬({d})" for d, pos in self.literals) or "true"


def blind_region(
    permission: str,
    lib: DetectionLibrary,
    account: Account,
    *,
    ctx: CoverageContext | None = None,
    max_cubes: int = 12,
) -> tuple[Cube, ...]:
    """The blind region of a permission as a formula (a DNF of prime implicants over the
    rules' own atomic tests and presence bits): ``Domain ∧ ¬⋁Observes`` projected onto the
    atoms of the fields the relevant rules read.  Each cube is *proven* against the exactly
    encoded rules: no event in it is observed by any of them.  Rules that needed an approximate
    atom (``unknown(...)``, reference lists, …) are left out — they *might* observe more, which
    is what the ``approximate`` flag on the permission already says.  This is the
    firewall-analysis representation — the whole hole, not one witness."""
    ctx = ctx or CoverageContext(lib)
    cat = account.catalog
    logged = sorted(m for m in cat.methods_for(permission) if account.logged(m))
    verified = [m for m in logged if cat.verified(m)]
    logged = verified or logged
    principals = sorted(account.principals_with(permission))
    if not logged or not principals:
        return ()
    # project onto every field an exactly-encoded rule that can fire on these methods reads
    # (rules naming one of them, and method-agnostic rules) plus the required fields
    from decnique.dsl.interpret import spec_methods_literal

    fields: set[str] = set()
    for m in logged:
        fields.update(cat.required_fields(m))
    for d in ctx.single_rules:
        if d.id not in ctx.exact_rules:
            continue
        lits = spec_methods_literal(d.spec)
        if lits and lits.isdisjoint(logged):
            continue
        for e in d.spec.events:
            for _, pth in referenced_fields(e.pred):
                fields.add(pth)
    skip = set(ENUMERATED) | {"service", "product_name", "event_type", "granted"}
    ev = ctx.enc.ev
    variables: list[tuple[z3.BoolRef, str, str]] = []  # (var, description, field)
    for f in sorted(fields - skip):
        pres = ev.present(f)
        if not z3.is_true(pres):
            variables.append((pres, f"{f} present", f))
        for a in ctx.table.by_field.get(f, ()):
            variables.append((ctx.table.var(a), describe_atom(a), f))
    domain = ctx.domain(permission, logged, principals, account)

    # a plain solver that asks the *opposite* question — is some event in the cube observed?
    obs = z3.Solver()
    obs.add(*domain, *ctx.consistency, *ctx.learned, ctx.any_obs_exact)

    def implicant(lits: list[tuple[z3.BoolRef, bool]]) -> bool:
        obs.push()
        obs.add(*[v if pos else z3.Not(v) for v, pos in lits])
        r = obs.check()
        obs.pop()
        return r == z3.unsat

    s = ctx.solver
    s.push()
    cubes: list[Cube] = []
    try:
        for c in domain:
            s.add(c)
        for _ in range(max_cubes):
            if s.check(*ctx.tracks.values()) != z3.sat:
                break
            model = s.model()
            lits = [(v, ctx._true(model, v)) for v, _, _ in variables]
            field_of = {v.get_id(): f for v, _, f in variables}
            proven = implicant(lits)
            if proven:
                # drop whole fields first (cheap, most are irrelevant), then single literals
                for f in sorted({f for _, _, f in variables}):
                    trial = [(v, pos) for v, pos in lits if field_of[v.get_id()] != f]
                    if trial != lits and implicant(trial):
                        lits = trial
                for i in range(len(lits) - 1, -1, -1):
                    trial = lits[:i] + lits[i + 1 :]
                    if implicant(trial):
                        lits = trial
            names = {v.get_id(): d for v, d, _ in variables}
            cubes.append(Cube(tuple((names[v.get_id()], pos) for v, pos in lits), proven))
            s.add(z3.Not(z3.And(*[v if pos else z3.Not(v) for v, pos in lits])))
    finally:
        s.pop()
    return tuple(cubes)
