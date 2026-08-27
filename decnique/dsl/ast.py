"""DSL AST (plan §5.10.3): detections, candidates, checks, rulesets and the loaded bundle.

Frozen dataclasses rather than pydantic models: the predicate and trace ASTs they
embed are dataclasses already, ``yaml_io`` handles (de)serialization, and nothing
downstream needs runtime validation beyond what ``parser.py`` performs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from decnique.model.predicates import Pred, QField, is_approximate, unknowns
from decnique.model.trace import TraceSpec

MetaValue = str | int | bool
CheckType = Literal[
    "coverage",
    "candidate",
    "compare",
    "dead_rules",
    "redundant_rules",
    "public_access",
    "boundary",
    "require_coverage",
    "attempt_coverage",
]
CHECK_TYPES: tuple[str, ...] = (
    "coverage",
    "candidate",
    "compare",
    "dead_rules",
    "redundant_rules",
    "public_access",
    "boundary",
    "require_coverage",
    "attempt_coverage",
)
CHECK_MODES: tuple[str, ...] = ("observed", "fires_single", "fires_bg")


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where a rule came from.  ``frontend`` is ``dsl`` for native rules."""

    file: str
    frontend: str = "dsl"
    line: int | None = None
    native_id: str | None = None
    unsupported: tuple[str, ...] = ()  # constructs that became Unknown atoms, by label
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Detection:
    id: str
    spec: TraceSpec
    meta: dict[str, MetaValue] = field(default_factory=dict)
    source: Provenance | None = None

    @property
    def approximate(self) -> bool:
        """True when any predicate holds an ``Unknown`` atom or the front-end dropped a
        construct (named in ``source.unsupported``) - the result must not be read as exact."""
        if any(is_approximate(e.pred) for e in self.spec.events):
            return True
        return bool(self.source and self.source.unsupported)

    @property
    def unknown_labels(self) -> tuple[str, ...]:
        return tuple(u.label for e in self.spec.events for u in unknowns(e.pred))

    @property
    def paradigm(self) -> str:
        """``event`` for single-event rules, ``correlation`` otherwise
        (data/detections/detection.md)."""
        return "event" if self.spec.is_single_event else "correlation"


@dataclass(frozen=True, slots=True)
class Required:
    permission: str
    where: Pred | None = None


@dataclass(frozen=True, slots=True)
class Step:
    id: str
    method: str
    repeat: int = 1
    within_seconds: int | None = None
    distinct: tuple[QField, ...] = ()
    where: Pred | None = None


@dataclass(frozen=True, slots=True)
class Footprint:
    steps: tuple[Step, ...]
    order: tuple[str, ...] = ()
    span_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class Candidate:
    id: str
    required: tuple[Required, ...]
    footprint: Footprint
    meta: dict[str, MetaValue] = field(default_factory=dict)
    actor: Pred | None = None
    context: Pred | None = None
    share: tuple[str, ...] = ("principal",)


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    type: str
    params: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Ruleset:
    id: str
    includes: tuple[str, ...] = ()
    disabled: frozenset[str] = frozenset()
    enabled: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class LoadIssue:
    severity: Literal["warning", "error"]
    file: str
    message: str
    rule_id: str | None = None


@dataclass(frozen=True, slots=True)
class Bundle:
    detections: tuple[Detection, ...] = ()
    candidates: tuple[Candidate, ...] = ()
    checks: tuple[Check, ...] = ()
    rulesets: tuple[Ruleset, ...] = ()
    issues: tuple[LoadIssue, ...] = ()

    def __add__(self, other: Bundle) -> Bundle:
        return Bundle(
            self.detections + other.detections,
            self.candidates + other.candidates,
            self.checks + other.checks,
            self.rulesets + other.rulesets,
            self.issues + other.issues,
        )

    @property
    def errors(self) -> tuple[LoadIssue, ...]:
        return tuple(i for i in self.issues if i.severity == "error")

    def detection(self, rule_id: str) -> Detection:
        for d in self.detections:
            if d.id == rule_id:
                return d
        raise KeyError(rule_id)

    def candidate(self, cand_id: str) -> Candidate:
        for c in self.candidates:
            if c.id == cand_id:
                return c
        raise KeyError(cand_id)


Item = Detection | Candidate | Check | Ruleset
