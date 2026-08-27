"""Privilege states and technique transitions (plan §M4).

A :class:`State` is the attacker's privilege configuration — the set of permissions currently
held (by the acting principal).  A :class:`Technique` is a transition **guarded** by its
candidate's ``Required`` permissions (they must hold in the current state) with a declared
**effect**: the permissions the attacker gains by executing it (mint a key, grant a role → Reach
grows).  Effects are a declared table for now, as the plan allows; the DSL can grow an effect
clause later.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from decnique.dsl.ast import Candidate
from decnique.env.model import Account, Grant

State = frozenset  # frozenset[str] of permissions held


@dataclass(frozen=True, slots=True)
class Technique:
    """A candidate lifted to a graph transition with a declared privilege effect."""

    candidate: Candidate
    gains: tuple[str, ...] = ()  # permissions added to the acting principal on success

    @property
    def id(self) -> str:
        return self.candidate.id

    @property
    def required(self) -> tuple[str, ...]:
        return tuple(r.permission for r in self.candidate.required)

    def applicable(self, state: State) -> bool:
        """The acting principal must already hold every Required permission."""
        return all(p in state for p in self.required)

    def apply(self, state: State) -> State:
        return frozenset(state | set(self.gains))


def account_for(base: Account, principal: str, state: State) -> Account:
    """The account as it stands in ``state``: ``principal`` holds exactly the state's
    permissions (on any resource); everything else — hierarchy, logging, catalog, other
    principals — is inherited from ``base``."""
    bindings = dict(base.bindings)
    bindings[principal] = tuple(Grant(permission=p, resource="*") for p in sorted(state))
    return Account(
        name=base.name,
        bindings=bindings,
        hierarchy=base.hierarchy,
        deny=base.deny,
        logging=base.logging,
        access_levels=base.access_levels,
        catalog=base.catalog,
    )
