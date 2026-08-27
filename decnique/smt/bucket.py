"""Permission-signature bucketing — the optional scale optimization (plan §M5).

The coverage solve for a permission depends only on its *coverage signature*: whether it is
reachable, which of its methods are logged, and which principals can exercise it (the rule set is
shared).  Permissions with an identical signature pose an identical ``find_gap`` problem and, Z3
being deterministic, yield an identical witness — so we solve once per signature and stamp the
rest.  This preserves results exactly while cutting solver invocations from O(#permissions) to
O(#signatures).

In practice the pruning that matters most is Invariant #2's reachability filter: for an account
that touches a handful of services, the reachable permission set is already small, so this
bucketing is a modest constant-factor win — hence "optional".
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from decnique.detections import DetectionLibrary
from decnique.env.model import Account
from decnique.smt.coverage import Gap, GapResult, find_gap


def coverage_signature(permission: str, account: Account) -> tuple:
    """Everything ``find_gap`` uses, minus the permission label: two permissions with the same
    signature have the same solve."""
    logged = frozenset(m for m in account.catalog.methods_for(permission) if account.logged(m))
    principals = frozenset(account.principals_with(permission))
    return (account.reachable(permission), logged, principals)


@dataclass(frozen=True, slots=True)
class BucketStats:
    permissions: int
    signatures: int

    @property
    def solver_calls_saved(self) -> int:
        return self.permissions - self.signatures

    @property
    def ratio(self) -> float:
        return self.signatures / self.permissions if self.permissions else 1.0


def bucketed_gaps(
    lib: DetectionLibrary,
    account: Account,
    permissions: tuple[str, ...],
) -> tuple[dict[str, GapResult], BucketStats]:
    """``find_gap`` for each permission, but solved once per signature and stamped onto the rest.

    Returns ``(results_by_permission, stats)``.  The results are identical to calling
    :func:`find_gap` on every permission individually (asserted by the M5 equivalence test)."""
    by_sig: dict[tuple, str] = {}
    solved: dict[str, GapResult] = {}
    results: dict[str, GapResult] = {}
    for p in permissions:
        sig = coverage_signature(p, account)
        rep = by_sig.get(sig)
        if rep is None:
            by_sig[sig] = p
            solved[sig] = find_gap(p, lib, account)  # one solve per signature
            results[p] = solved[sig]
        else:
            results[p] = _relabel(solved[coverage_signature(rep, account)], p)
    return results, BucketStats(permissions=len(permissions), signatures=len(by_sig))


def _relabel(result: GapResult, permission: str) -> GapResult:
    if isinstance(result, Gap):
        return replace(result, permission=permission)
    return replace(result, permission=permission)
