"""Concrete multi-event evaluation (plan Milestone M0).

The single-event interpreter (:mod:`decnique.dsl.interpret`) answers ``Observes(R, e)``
for one event.  This package lifts that to the *temporal* part of the language: it
evaluates a whole :class:`~decnique.model.trace.TraceSpec` (joins, grouping, windows,
ordering, aggregates and the count/aggregate condition) and a candidate
:class:`~decnique.dsl.ast.Footprint` against an ordered list of concrete events.

Evaluation stays three-valued (``yes`` / ``no`` / ``don't know``): an ``Unknown`` atom,
an absent reference list, or a missing timestamp makes the outcome uncertain rather
than a confident boolean.  This is the ground-truth oracle every symbolic milestone is
differentially tested against, so it favours obvious correctness over cleverness.
"""

from __future__ import annotations

from decnique.eval.trace_eval import fires, match_event_var, matches_footprint

__all__ = ["fires", "match_event_var", "matches_footprint"]
