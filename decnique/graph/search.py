"""Search for stealthy privilege-escalation chains (plan §M4).

From an initial :class:`~decnique.graph.state.State` to a goal permission, find a path where
**every hop is stealth-feasible** — its technique realizes a schedule that no rule fires on, in
the account as it stands at that point in the chain (Reach grows hop by hop).  Each hop's stealth
witness is produced (and replay-verified) by M3, so a returned :class:`StealthyPath` is valid
hop-by-hop.  When no stealthy path exists the search proves it by exhausting the finite reachable
state space (the permission universe is finite), not by giving up at a bound.

"Detection-priced": :func:`price_transitions` annotates each technique at a state with whether it
is stealthy or forced to trip a rule, for the thesis's detection-priced graphs.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from decnique.detections import DetectionLibrary
from decnique.env.model import Account
from decnique.graph.state import State, Technique, account_for
from decnique.smt.stealth import Evasive, StealthResult, stealth_feasible


@dataclass(frozen=True, slots=True)
class Hop:
    technique: str
    principal: str
    from_state: frozenset
    to_state: frozenset
    schedule: tuple[dict, ...]
    approximate: bool
    unknown_rules: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StealthyPath:
    hops: tuple[Hop, ...]
    goal: str

    @property
    def approximate(self) -> bool:
        return any(h.approximate for h in self.hops)

    @property
    def found(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class NoStealthyPath:
    goal: str
    states_explored: int
    reason: str = "exhausted"  # exhausted | depth_bound

    @property
    def found(self) -> bool:
        return False


PathResult = StealthyPath | NoStealthyPath


def _goal_pred(goal: str | Callable[[State], bool]) -> Callable[[State], bool]:
    if callable(goal):
        return goal
    return lambda s: goal in s


def search_stealth_path(
    techniques: list[Technique],
    lib: DetectionLibrary,
    base_account: Account,
    principal: str,
    initial_state: State,
    goal: str,
    *,
    max_depth: int | None = None,
) -> PathResult:
    """Breadth-first search for a shortest stealthy chain from ``initial_state`` to ``goal``.

    Explores the (finite) reachable state space fully; ``max_depth`` optionally caps chain length
    and, if it truncates the search, is reported as ``reason='depth_bound'`` (no silent cap)."""
    goal_reached = _goal_pred(goal)
    start = frozenset(initial_state)
    if goal_reached(start):
        return StealthyPath(hops=(), goal=str(goal))

    visited: set[frozenset] = {start}
    # queue holds (state, path-of-hops)
    queue: deque[tuple[frozenset, tuple[Hop, ...]]] = deque([(start, ())])
    explored = 0
    truncated = False

    while queue:
        state, path = queue.popleft()
        explored += 1
        if max_depth is not None and len(path) >= max_depth:
            truncated = True
            continue
        account = account_for(base_account, principal, state)
        for tech in techniques:
            if not tech.applicable(state):
                continue
            nxt = tech.apply(state)
            if nxt == state or nxt in visited:
                continue
            result: StealthResult = stealth_feasible(tech.candidate, lib, account)
            if not isinstance(result, Evasive):
                continue  # this hop is not stealthy in this state
            hop = Hop(
                technique=tech.id,
                principal=principal,
                from_state=state,
                to_state=nxt,
                schedule=result.schedule,
                approximate=result.approximate,
                unknown_rules=result.unknown_rules,
            )
            new_path = path + (hop,)
            if goal_reached(nxt):
                return StealthyPath(hops=new_path, goal=str(goal))
            visited.add(nxt)
            queue.append((nxt, new_path))

    return NoStealthyPath(
        goal=str(goal),
        states_explored=explored,
        reason="depth_bound" if truncated else "exhausted",
    )


@dataclass(frozen=True, slots=True)
class PricedEdge:
    technique: str
    stealthy: bool
    verdict: str
    approximate: bool


def price_transitions(
    techniques: list[Technique],
    lib: DetectionLibrary,
    base_account: Account,
    principal: str,
    state: State,
) -> tuple[PricedEdge, ...]:
    """For each applicable technique at ``state``, whether it can be run stealthily or is forced
    to trip a rule (its "detection price")."""
    account = account_for(base_account, principal, state)
    edges: list[PricedEdge] = []
    for tech in techniques:
        if not tech.applicable(state):
            continue
        r = stealth_feasible(tech.candidate, lib, account)
        stealthy = isinstance(r, Evasive)
        edges.append(
            PricedEdge(
                technique=tech.id,
                stealthy=stealthy,
                verdict=r.verdict,
                approximate=isinstance(r, Evasive) and r.approximate,
            )
        )
    return tuple(edges)
