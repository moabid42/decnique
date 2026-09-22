"""Holes as regions — the coverage-gap plan, phases 1–3.

``ask blindspots`` and ``ask stealth`` answer with one witness event.  This package answers with
the *whole* set: for a technique, every run over which no rule fires, written as ranges over the
technique's own free variables (``count ∈ …``, ``span ∈ …``, a field pinned to a value) with a
concrete, replayed run inside each one.

Build order, and where each piece of the plan lives:

* :mod:`decnique.regions.domains`  — §4, the per-axis set algebra (numeric, categorical, boolean)
* :mod:`decnique.regions.boxes`    — §4.8, §7.1, §7.3, boxes and their difference
* :mod:`decnique.regions.compile`  — §5, a rule predicate to a union of boxes
* :mod:`decnique.regions.backends` — §7.3–§7.5, the interval and SMT backends, and the choice
* :mod:`decnique.regions.technique`— §6, §7.2, §9.1, one technique's variable space and report
"""

from __future__ import annotations

from decnique.regions.backends import BACKENDS, solve
from decnique.regions.boxes import (
    Axis,
    Box,
    Difference,
    Space,
    box_subtract,
    classify,
    subtract_all,
)
from decnique.regions.compile import CompiledRule, compile_rule
from decnique.regions.domains import NA, Categorical, Domain, Numeric
from decnique.regions.technique import Hole, RegionReport, region_report

__all__ = [
    "BACKENDS",
    "NA",
    "Axis",
    "Box",
    "Categorical",
    "CompiledRule",
    "Difference",
    "Domain",
    "Hole",
    "Numeric",
    "RegionReport",
    "Space",
    "box_subtract",
    "classify",
    "compile_rule",
    "region_report",
    "solve",
    "subtract_all",
]
