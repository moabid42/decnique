"""Symbolic single-event coverage — ``Reach ∧ Log ∧ ¬⋁Observes`` (plan §M2).

:func:`find_gap` searches for one event that uses a permission, is reachable and logged in the
account, and that **no** detection fires on.  The symbolic layer only *proposes* events; every
proposal is decoded and replayed through the concrete M0 oracle (:func:`decnique.eval.fires`)
and the M1 account (``reach`` / ``logged``).  A proposal a rule actually fires on is blocked and
the search continues, so the result is sound by construction (Invariant #3): a returned ``Gap``
is a concrete event that is provably reachable, logged, and unobserved.

Honesty (Invariant #1): if any detection returns *don't know* on the witness (e.g. its only
handle on the permission was an ``Unknown`` atom), the gap is reported ``approximate``.
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
from decnique.smt.encode_event import SymEvent
from decnique.smt.encode_pred import Encoder


@dataclass(frozen=True, slots=True)
class Gap:
    """A concrete, replay-verified blind-spot event for one permission."""

    permission: str
    event: dict
    approximate: bool
    unknown_rules: tuple[str, ...] = ()

    @property
    def found(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class NoGap:
    """No blind spot for this permission (or none within the refinement bound)."""

    permission: str
    reason: str  # unreachable | no_logged_method | all_covered | exhausted

    @property
    def found(self) -> bool:
        return False


GapResult = Gap | NoGap


@dataclass
class _Probe:
    """Reusable per-permission symbolic problem."""

    ev: SymEvent
    enc: Encoder
    paths: tuple[str, ...]
    solver: z3.Solver = field(default_factory=z3.Solver)


def _observes_formula(enc: Encoder, spec) -> z3.BoolRef:  # type: ignore[no-untyped-def]
    """Single-event ``Observes``: the (only) event variable's predicate under the zero-value
    guard (every referenced field present, unless ``allow_zero_values``)."""
    var = spec.events[0]
    body = enc.pred(var.pred)
    if spec.options.allow_zero_values:
        return body
    guard = [enc.ev.present(path) for _, path in referenced_fields(var.pred)]
    return z3.And(body, *guard) if guard else body


def _decode(ev: SymEvent, model: z3.ModelRef, paths: tuple[str, ...]) -> dict:
    out: dict = {}
    for path in paths:
        if not _present(ev, model, path):
            continue
        val = _decode_term(ev, model, path)
        if val is not None:
            out[path] = val
    return out


def _present(ev: SymEvent, model: z3.ModelRef, path: str) -> bool:
    pres = ev.present(path)
    if z3.is_true(pres):
        return True
    v = model.eval(pres, model_completion=True)
    return z3.is_true(v)


def _decode_term(ev: SymEvent, model: z3.ModelRef, path: str):  # -> value | None
    sort = ev.sort_of(path)
    term = ev.term(path)
    v = model.eval(term, model_completion=True)
    if sort in ("string", "strings"):
        return v.as_string()
    if sort in ("int", "time"):
        return v.as_long()
    if sort == "bool":
        return z3.is_true(v)
    if sort == "ip":
        return str(ipaddress.IPv4Address(v.as_long() & 0xFFFFFFFF))
    return v.as_string()


def _block(ev: SymEvent, model: z3.ModelRef, paths: tuple[str, ...]) -> z3.BoolRef:
    """A clause excluding exactly this assignment over the referenced fields."""
    diffs: list[z3.BoolRef] = []
    for path in paths:
        pres = ev.present(path)
        present_now = _present(ev, model, path)
        if not z3.is_true(pres):
            diffs.append(pres if not present_now else z3.Not(pres))
        if present_now:
            term = ev.term(path)
            diffs.append(term != model.eval(term, model_completion=True))
    return z3.Or(*diffs) if diffs else z3.BoolVal(False)


def _probe_paths(lib: DetectionLibrary) -> tuple[str, ...]:
    paths = {"method", "principal", "resource"}
    for d in lib.detections:
        if d.spec.is_single_event:
            for _, p in referenced_fields(d.spec.events[0].pred):
                paths.add(p)
    return tuple(sorted(paths))


def find_gap(
    permission: str,
    lib: DetectionLibrary,
    account: Account,
    *,
    max_refine: int = 64,
) -> GapResult:
    """Solve ``Reach ∧ Log ∧ ¬⋁Observes`` for one permission; return a verified witness."""
    cat = account.catalog
    if not account.reachable(permission):
        return NoGap(permission, "unreachable")
    logged = sorted(m for m in cat.methods_for(permission) if account.logged(m))
    if not logged:
        return NoGap(permission, "no_logged_method")
    principals = sorted(account.principals_with(permission))
    if not principals:
        return NoGap(permission, "unreachable")

    ev = SymEvent(prefix="e")
    enc = Encoder(ev=ev)
    paths = _probe_paths(lib)
    s = z3.Solver()
    s.set("random_seed", 0)  # reproducible witnesses (plan §4: reproducible numbers)

    # domain: a logged, permission-relevant method attributable to an allowed principal
    s.add(z3.Or(*[ev.term("method") == z3.StringVal(m) for m in logged]))
    s.add(ev.present("principal"))
    s.add(z3.Or(*[ev.term("principal") == z3.StringVal(p) for p in principals]))

    single_rules = [d for d in lib.detections if d.spec.is_single_event]
    obs = [_observes_formula(enc, d.spec) for d in single_rules]
    if obs:
        s.add(z3.Not(z3.Or(*obs)))

    for _ in range(max_refine):
        if s.check() != z3.sat:
            return NoGap(permission, "all_covered")
        model = s.model()
        event = _decode(ev, model, paths)
        event.setdefault("method", None)
        # Reach on the *decoded* principal + resource (globs may not cover it) and Log.
        principal = event.get("principal")
        resource = event.get("resource", "*")
        if not account.logged(event.get("method")) or not account.reach(
            principal, permission, resource
        ):
            s.add(_block(ev, model, paths))
            continue
        # Concrete oracle is authoritative: does ANY rule fire / is any uncertain?
        verdicts = {d.id: fires(d.spec, [event], ref_lists=lib.ref_lists) for d in lib.detections}
        if any(v is True for v in verdicts.values()):
            s.add(_block(ev, model, paths))  # a rule really fires → not a gap; refine
            continue
        unknown_rules = tuple(rid for rid, v in verdicts.items() if v is None)
        return Gap(
            permission=permission,
            event=event,
            approximate=bool(unknown_rules),
            unknown_rules=unknown_rules,
        )
    return NoGap(permission, "exhausted")


@dataclass(frozen=True, slots=True)
class CoverageReport:
    gaps: tuple[Gap, ...]
    covered: tuple[str, ...]
    unreachable: tuple[str, ...]
    unlogged: tuple[str, ...]
    approximate: tuple[str, ...]

    def summary(self) -> dict:
        return {
            "permissions_probed": len(self.gaps)
            + len(self.covered)
            + len(self.unreachable)
            + len(self.unlogged),
            "gaps": len(self.gaps),
            "approximate": len(self.approximate),
            "covered": len(self.covered),
            "unreachable": len(self.unreachable),
            "unlogged": len(self.unlogged),
        }


def probe_permissions(
    lib: DetectionLibrary,
    account: Account,
    permissions: tuple[str, ...] | None = None,
) -> CoverageReport:
    """Probe a set of permissions (default: every catalog permission the account can reach)."""
    if permissions is None:
        permissions = tuple(
            sorted(p for p in account.catalog.all_permissions() if account.reachable(p))
        )
    gaps: list[Gap] = []
    covered: list[str] = []
    unreachable: list[str] = []
    unlogged: list[str] = []
    approximate: list[str] = []
    for p in permissions:
        r = find_gap(p, lib, account)
        if isinstance(r, Gap):
            gaps.append(r)
            if r.approximate:
                approximate.append(p)
        elif r.reason == "unreachable":
            unreachable.append(p)
        elif r.reason == "no_logged_method":
            unlogged.append(p)
        else:
            covered.append(p)
    return CoverageReport(
        gaps=tuple(gaps),
        covered=tuple(covered),
        unreachable=tuple(unreachable),
        unlogged=tuple(unlogged),
        approximate=tuple(approximate),
    )
