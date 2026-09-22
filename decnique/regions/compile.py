"""Rule → boxes — the coverage-gap plan §5.

One detection predicate becomes a finite union of boxes: negation is pushed inward, the result
is turned into DNF, and each conjunct becomes one box by intersecting the per-attribute
constraints.  An attribute the conjunct never mentions is left out, which means the whole axis.

**The under-approximation policy (§5.4) is the important part.**  When a conjunct contains
something this compiler cannot express — a comparison between two attributes, a reference list
whose contents are not loaded, an ``unknown(...)`` the front-ends could not translate — the
*whole rule is dropped* and listed with a reason.  Dropping shrinks the covered region, so it
can only invent a hole that the report labels as needing a manual check; keeping a
half-understood rule would *enlarge* it and could hide a real blind spot.  That is the same
honesty rule as invariant #1, stated for regions.

**Closed axes are expanded exactly (§4.7).**  A glob or regex is not a set operation, so it
cannot be a constraint — but when an axis has a declared value list (the methods of a
permission, a boolean), each value is simply handed to decnique's own leaf interpreter and kept
if it matches.  The rule's region is then exact *by construction against the engine that
decides `fires`*, which is what the consistency check of §8.4 verifies.

**Null semantics (§5.5) are two-valued here**, because that is what
:func:`decnique.dsl.interpret.evaluate` does: a leaf on a field the event does not carry is
``False``, so ``NOT (window < 600)`` *includes* the missing value.  It falls out of the algebra
rather than being special-cased: every leaf compiles to a region with ``NA`` excluded, and a
negation is ``TOP \\ region``, which puts ``NA`` back.
"""

from __future__ import annotations

from dataclasses import dataclass

from decnique.dsl.interpret import _leaf as concrete_leaf
from decnique.model import event_fields as ef
from decnique.model.predicates import (
    All,
    Any,
    Cmp,
    Const,
    Exists,
    In,
    InCidr,
    InList,
    Leaf,
    Like,
    Not,
    Pred,
    Regex,
    StrFn,
    Unknown,
    normalize,
)
from decnique.regions.boxes import Axis, Box, Space, categorical_axis, numeric_axis
from decnique.regions.domains import BOOL_UNIVERSE, NA, Categorical, Domain, Numeric, Point

DEFAULT_MAX_BOXES = 256  # plan D7: a rule whose DNF is wider than this is dropped and flagged


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """One rule as a union of boxes, or nothing at all with a reason."""

    id: str
    boxes: tuple[Box, ...]
    dropped: bool = False
    warnings: tuple[str, ...] = ()

    @property
    def covers_nothing(self) -> bool:
        return not self.boxes


class Unsupported(Exception):
    """Raised inside the compiler; caught at the top and turned into a dropped rule."""


def axis_for_field(path: str, universe: frozenset[Point] | None = None) -> Axis:
    """The axis one event field becomes.  Numbers stay numbers; everything else — strings, IPs,
    booleans — is categorical, because coverage needs set operations and never a distance."""
    sort = ef.field_sort(path)
    if sort in ("int", "time"):
        return numeric_axis(path, unit="", doc=sort)
    if sort == "bool":
        return categorical_axis(path, BOOL_UNIVERSE, doc=sort)
    return categorical_axis(path, universe, doc=sort)


def compile_rule(
    rule_id: str, pred: Pred, space: Space, *, max_boxes: int = DEFAULT_MAX_BOXES
) -> CompiledRule:
    """Compile one single-event predicate to a union of boxes over ``space``."""
    try:
        boxes = _dnf(normalize(pred), space, max_boxes)
    except Unsupported as e:
        return CompiledRule(id=rule_id, boxes=(), dropped=True, warnings=(str(e),))
    kept = tuple(b for b in boxes if not b.is_empty())
    return CompiledRule(id=rule_id, boxes=kept)


# --- DNF ---------------------------------------------------------------------------------------


def _dnf(p: Pred, space: Space, cap: int) -> list[Box]:
    if isinstance(p, Const):
        return [space.top()] if p.value else []
    if isinstance(p, Unknown):
        raise Unsupported(f"unknown({p.label}) — the front-end could not translate this test")
    if isinstance(p, Any):
        out: list[Box] = []
        for c in p.children:
            out.extend(_dnf(c, space, cap))
            if len(out) > cap:
                raise Unsupported(f"more than {cap} boxes after expanding the disjunctions")
        return out
    if isinstance(p, All):
        acc: list[Box] = [space.top()]
        for c in p.children:
            child = _dnf(c, space, cap)
            if len(acc) * len(child) > cap:
                raise Unsupported(f"more than {cap} boxes after expanding the disjunctions")
            acc = [a.intersect(b) for a in acc for b in child]
            acc = [b for b in acc if not b.is_empty()]
            if not acc:
                return []
        return acc
    if isinstance(p, Not):
        # `normalize` pushes negation to the leaves, so this is a negated leaf.  Its region is
        # the axis minus the leaf's region, which is also what puts the missing value back in:
        # a leaf is false on a field the event does not carry, so its negation is true there.
        name, alts = _leaf_alternatives(p.child, space)
        pieces: list[Domain] = [space.axis(name).top]
        for v in alts:
            pieces = [q for piece in pieces for q in piece.subtract(v)]
        return [space.box({name: piece}) for piece in pieces]
    name, alts = _leaf_alternatives(p, space)
    return [space.box({name: v}) for v in alts]


# --- one leaf ----------------------------------------------------------------------------------


def _leaf_alternatives(p: Pred, space: Space) -> tuple[str, tuple[Domain, ...]]:
    """The region one leaf denotes, as disjoint pieces on a single axis.

    A leaf can need more than one piece: ``time != 5`` is everything below 5 together with
    everything above it.  Every piece excludes ``NA`` (two-valued §5.5), which is what makes the
    negation above come out right without a special case.
    """
    if isinstance(p, (Not, All, Any, Const, Unknown)):
        raise Unsupported("a negation over more than one test")
    name = _axis_name(p, space)
    axis = space.axis(name)
    if isinstance(p, Exists):
        return name, (_present(axis),)
    if p.quant is not None or ef.is_repeated(name):
        # one axis carries one value; "every element of a repeated field" is a different
        # question and answering it here would silently model a different rule
        raise Unsupported(f"a quantified test over the repeated field {name}")
    if isinstance(p, InList):
        raise Unsupported(f"reference list %{p.list_name} — its contents are not loaded")
    universe = _universe(axis)
    if universe is not None:
        return name, (_expand(p, universe),)
    if isinstance(axis.top, Numeric):
        return name, _numeric_leaf(p, name)
    return name, (_categorical_leaf(p, name),)


def _axis_name(p: Pred, space: Space) -> str:
    path = p.field[1] if isinstance(p, (Exists, *_LEAVES)) else None
    if path is None:
        raise Unsupported("a test with no field")
    if path not in space.names():
        raise Unsupported(f"{path} is not an axis of this candidate")
    return path


_LEAVES = (Cmp, Like, Regex, StrFn, In, InCidr, InList)


def _present(axis: Axis) -> Domain:
    return Numeric(na=False) if isinstance(axis.top, Numeric) else Categorical.but(NA)


def _universe(axis: Axis) -> frozenset[Point] | None:
    top = axis.top
    return top.universe if isinstance(top, Categorical) else None


def _expand(p: Pred, universe: frozenset[Point]) -> Categorical:
    """A closed axis: ask the interpreter, value by value.  Exact for every leaf kind — globs
    and regexes included — and exact *against the oracle that decides whether a rule fires*."""
    keep: set[Point] = set()
    for v in universe:
        if v is NA:
            continue  # two-valued: a leaf is false on a value the event does not carry
        verdict = concrete_leaf(p, v, None)
        if verdict is None:
            raise Unsupported(f"{type(p).__name__} on a value the interpreter cannot decide")
        if verdict:
            keep.add(v)
    return Categorical(values=frozenset(keep), include=True, universe=universe)


def _numeric_leaf(p: Pred, name: str) -> tuple[Numeric, ...]:
    if isinstance(p, Cmp) and _is_int(p.value):
        n = int(p.value)  # type: ignore[arg-type]
        if p.op == "=":
            return (Numeric.exactly(n),)
        if p.op == "!=":  # a union, not an interval — the reason a leaf may need two pieces
            return (Numeric.at_most(n - 1), Numeric.at_least(n + 1))
        if p.op == "<":
            return (Numeric.at_most(n - 1),)
        if p.op == "<=":
            return (Numeric.at_most(n),)
        if p.op == ">":
            return (Numeric.at_least(n + 1),)
        if p.op == ">=":
            return (Numeric.at_least(n),)
    if isinstance(p, In) and all(_is_int(v) for v in p.values):
        # one piece per value: collapsing them to [min, max] would *enlarge* the rule, and an
        # enlarged rule hides holes (plan §2.4)
        return tuple(Numeric.exactly(int(v)) for v in p.values)  # type: ignore[arg-type]
    raise Unsupported(f"{type(p).__name__} on the numeric axis {name}")


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _categorical_leaf(p: Pred, name: str) -> Categorical:
    if isinstance(p, Cmp):
        if p.op == "=":
            return Categorical.of(_fold(p))
        if p.op == "!=":
            # everything else, but still not the missing value: `method != "X"` is false on an
            # event that carries no method at all
            return Categorical.but(_fold(p), NA)
        raise Unsupported(f"{p.op} on the open axis {name}")
    if isinstance(p, In):
        return Categorical(values=frozenset(_fold_all(p)), include=True)
    raise Unsupported(f"{type(p).__name__} on the open axis {name} — no closed value list")


def _fold(p: Cmp) -> Point:
    return str(p.value).lower() if p.nocase and isinstance(p.value, str) else p.value


def _fold_all(p: In) -> tuple[Point, ...]:
    return tuple(str(v).lower() if p.nocase and isinstance(v, str) else v for v in p.values)


def leaf_fields(p: Pred) -> frozenset[str]:
    """Field paths a predicate tests — the axes a space must carry to compile it."""
    out: set[str] = set()
    _walk(p, out)
    return frozenset(out)


def _walk(p: Pred, out: set[str]) -> None:
    if isinstance(p, (All, Any)):
        for c in p.children:
            _walk(c, out)
    elif isinstance(p, Not):
        _walk(p.child, out)
    elif isinstance(p, (Exists, *_LEAVES)):
        assert isinstance(p, (Exists, Leaf))
        out.add(p.field[1])
    elif isinstance(p, Unknown):
        for qf in p.fields:
            out.add(qf[1])
