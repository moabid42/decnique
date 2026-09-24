"""Resource-scoped Reach for a symbolic event, replayed against Account before acceptance."""

from __future__ import annotations

from fnmatch import fnmatchcase

import z3

from decnique.env.model import Account, _perm_match
from decnique.smt.encode_event import SymEvent
from decnique.smt.encode_pred import _glob_to_re


def reach_constraint(
    event: SymEvent, account: Account, principal: str, permission: str,
) -> tuple[z3.BoolRef, bool]:
    resource = event.term("resource")
    exact = True

    def scope(pattern: str) -> z3.BoolRef:
        nonlocal exact
        if "[" in pattern:
            # Account accepts fnmatch classes; the SIEM glob encoder does not. Leave a fresh
            # proposal atom and require replay; it cannot support an infeasibility proof.
            exact = False
            direct = z3.FreshBool(f"{event.prefix}.resource_scope")
        else:
            direct = z3.InRe(resource, _glob_to_re(pattern, False))
        descendants = [
            resource == child for child in account.hierarchy
            if any(fnmatchcase(parent, pattern) for parent in account._ancestors(child)[1:])
        ]
        return z3.Or(direct, *descendants)

    grants = [scope(g.resource) for g in account.bindings.get(principal, ())
              if _perm_match(g.permission, permission)]
    denies = [scope(d.resource) for d in account.deny
              if d.principal in (principal, "*", "allUsers") and _perm_match(d.permission, permission)]
    return z3.And(z3.Or(*grants), z3.Not(z3.Or(*denies))), exact
