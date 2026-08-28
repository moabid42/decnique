"""Symbolic coverage & stealth search over the event model (plan §M2–M3, Z3-backed).

The encoders (:mod:`~decnique.smt.encode_event`, :mod:`~decnique.smt.encode_pred`,
:mod:`~decnique.smt.encode_trace`) lower the DSL onto Z3; :mod:`~decnique.smt.coverage` and
:mod:`~decnique.smt.stealth` pose the coverage and stealth questions.  Every symbolic witness is
replayed through the concrete M0 oracle and the M1 account before it is reported, so results are
sound regardless of encoding precision (Invariant #3).
"""

from __future__ import annotations

from decnique.smt.bucket import BucketStats, bucketed_gaps, coverage_signature
from decnique.smt.coverage import (
    CoverageContext,
    CoverageReport,
    Gap,
    GapResult,
    NoGap,
    find_gap,
    probe_permissions,
)
from decnique.smt.stealth import (
    AlwaysDetected,
    Evasive,
    Exhausted,
    NotFeasible,
    StealthResult,
    feasible,
    stealth_feasible,
)

__all__ = [
    "AlwaysDetected",
    "BucketStats",
    "CoverageContext",
    "CoverageReport",
    "bucketed_gaps",
    "coverage_signature",
    "Evasive",
    "Exhausted",
    "Gap",
    "GapResult",
    "NoGap",
    "NotFeasible",
    "StealthResult",
    "feasible",
    "find_gap",
    "probe_permissions",
    "stealth_feasible",
]
