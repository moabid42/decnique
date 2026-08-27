"""Attack-graph search for stealthy privilege-escalation chains (plan §M4).

Lifts single-technique stealth (M3) to paths over privilege **states**: a chain is stealthy iff
every hop is stealth-feasible in the account as it stands at that hop, with Reach growing as the
attacker gains permissions.
"""

from __future__ import annotations

from decnique.graph.search import (
    Hop,
    NoStealthyPath,
    PathResult,
    PricedEdge,
    StealthyPath,
    price_transitions,
    search_stealth_path,
)
from decnique.graph.state import State, Technique, account_for

__all__ = [
    "Hop",
    "NoStealthyPath",
    "PathResult",
    "PricedEdge",
    "State",
    "StealthyPath",
    "Technique",
    "account_for",
    "price_transitions",
    "search_stealth_path",
]
