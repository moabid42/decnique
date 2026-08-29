"""Search for stealthy privilege-escalation chains (plan §M4).

From an initial :class:`~decnique.graph.state.State` to a goal permission, find a path where
**every hop is stealth-feasible** — its technique realizes a schedule that no rule fires on, in
the account as it stands at that point in the chain (Reach grows hop by hop).  Each hop's stealth
witness is produced (and replay-verified) by M3, and the **whole path** is then replayed as one
trace (hop schedules laid end to end, with a delay between hops chosen so that no rule fires;
see :func:`_path_replay`) — a correlation rule such as "key created *then* token minted within
an hour" is invisible to a hop-by-hop check, so a returned :class:`StealthyPath` is only
believed after this replay.  When no stealthy path exists the search reports it by exhausting
the finite reachable state space (with the hop schedules M3 chose — not every schedule).

"Detection-priced": :func:`price_transitions` annotates each technique at a state with whether it
is stealthy or forced to trip a rule, for the thesis's detection-priced graphs.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from decnique.detections import DetectionLibrary
from decnique.env.model import Account
from decnique.eval import fires
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
    delay: int = 0  # seconds waited after the previous hop before this one starts


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


def _shift(schedule: tuple[dict, ...], offset: int) -> tuple[dict, ...]:
    return tuple({**e, "time": int(e.get("time", 0)) + offset} for e in schedule)


def _span(events: tuple[dict, ...]) -> int:
    return max((int(e.get("time", 0)) for e in events), default=0)


def _path_replay(
    lib: DetectionLibrary, account: Account, path: tuple[Hop, ...], schedule: tuple[dict, ...]
) -> tuple[int, tuple[str, ...]] | None:
    """Replay the path so far plus ``schedule`` as one trace.  Tries the hop back to back, then
    after a delay longer than every rule window (a patient attacker).  Returns the delay that
    works and the rules that answered *don't-know*, or ``None`` when some rule fires on every
    tried delay."""
    prior: tuple[dict, ...] = ()
    for h in path:
        prior += _shift(h.schedule, _span(prior) + h.delay)
    windows = [d.spec.window.seconds for d in lib.detections if d.spec.window is not None]
    delays = [0] + ([max(windows) + 1] if windows else [])
    for delay in delays:
        whole = prior + _shift(schedule, (_span(prior) + delay) if prior else 0)
        seen = [e for e in whole if account.logged(str(e.get("method", "")))]
        verdicts = {d.id: fires(d.spec, seen, ref_lists=lib.ref_lists) for d in lib.detections
                    if fires(d.spec, [], ref_lists=lib.ref_lists) is not True}
        if any(v is True for v in verdicts.values()):
            continue
        return delay, tuple(r for r, v in verdicts.items() if v is None)
    return None


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
            whole = _path_replay(lib, account, path, result.schedule)
            if whole is None:
                continue  # stealthy alone, but a rule correlates it with an earlier hop
            delay, unknown = whole
            hop = Hop(
                technique=tech.id,
                principal=principal,
                from_state=state,
                to_state=nxt,
                schedule=result.schedule,
                approximate=result.approximate or bool(unknown),
                unknown_rules=tuple(dict.fromkeys(result.unknown_rules + unknown)),
                delay=delay,
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
