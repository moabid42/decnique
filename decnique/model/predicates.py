"""Single-event predicate AST (plan §5.3).

A predicate is a tree over *qualified fields* ``QField = (event_var | None, field_path)``.
``event_var`` is ``None`` for the implicit single event variable.  Field paths are the
event-model names of :mod:`decnique.model.event_fields`; a path starting with ``udm:``
names a raw UDM field that the event model does not interpret (it stays a leaf here and
lowers to an uninterpreted atom in the symbolic encoders).

Every leaf carries ``nocase`` (case-insensitive match) and ``quant`` (``"all"``/``"any"``
for repeated fields; ``None`` means ``any``).  :class:`Unknown` is an atom the front-ends
could not translate; any predicate containing one makes a result *approximate*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

QField = tuple[str | None, str]
Value = str | int | bool
CmpOp = Literal["=", "!=", "<", "<=", ">", ">="]
Quant = Literal["all", "any"] | None
StrFnName = Literal["startswith", "endswith", "contains"]
ListKind = Literal["string", "regex", "cidr"]


@dataclass(frozen=True, slots=True, kw_only=True)
class Leaf:
    field: QField
    nocase: bool = False
    quant: Quant = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Cmp(Leaf):
    op: CmpOp
    value: Value


@dataclass(frozen=True, slots=True, kw_only=True)
class Like(Leaf):
    """Glob: ``*`` any run of characters, ``?`` exactly one."""

    pattern: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Regex(Leaf):
    """RE2-style regular expression, partial (unanchored) match unless anchored."""

    pattern: str


@dataclass(frozen=True, slots=True, kw_only=True)
class StrFn(Leaf):
    fn: StrFnName
    value: str


@dataclass(frozen=True, slots=True, kw_only=True)
class In(Leaf):
    values: tuple[Value, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class InCidr(Leaf):
    cidrs: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class InList(Leaf):
    """SecOps reference list / data-table column (``in %name``)."""

    list_name: str
    kind: ListKind = "string"


@dataclass(frozen=True, slots=True, kw_only=True)
class Exists:
    field: QField


@dataclass(frozen=True, slots=True, kw_only=True)
class Const:
    value: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class Unknown:
    """An atom the encoders cannot interpret.  ``label`` names the construct."""

    label: str
    raw: str | None = None
    fields: tuple[QField, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class Not:
    child: Pred


@dataclass(frozen=True, slots=True, kw_only=True)
class All:
    children: tuple[Pred, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True, kw_only=True)
class Any:
    children: tuple[Pred, ...] = field(default_factory=tuple)


Pred = (
    Cmp | Like | Regex | StrFn | In | InCidr | InList | Exists | Const | Unknown | Not | All | Any
)
LEAF_TYPES = (Cmp, Like, Regex, StrFn, In, InCidr, InList)


def referenced_fields(p: Pred) -> frozenset[QField]:
    """Every qualified field the predicate mentions (including inside ``Unknown``)."""
    if isinstance(p, LEAF_TYPES):
        return frozenset({p.field})
    if isinstance(p, Exists):
        return frozenset({p.field})
    if isinstance(p, Unknown):
        return frozenset(p.fields)
    if isinstance(p, Not):
        return referenced_fields(p.child)
    if isinstance(p, All | Any):
        out: set[QField] = set()
        for c in p.children:
            out |= referenced_fields(c)
        return frozenset(out)
    return frozenset()


def event_vars(p: Pred) -> frozenset[str]:
    return frozenset(v for v, _ in referenced_fields(p) if v is not None)


def unknowns(p: Pred) -> tuple[Unknown, ...]:
    if isinstance(p, Unknown):
        return (p,)
    if isinstance(p, Not):
        return unknowns(p.child)
    if isinstance(p, All | Any):
        return tuple(u for c in p.children for u in unknowns(c))
    return ()


def is_approximate(p: Pred) -> bool:
    return bool(unknowns(p))


def all_of(children: list[Pred] | tuple[Pred, ...]) -> Pred:
    """Conjunction with the obvious simplifications (no NNF; use :func:`normalize`)."""
    flat: list[Pred] = []
    for c in children:
        if isinstance(c, Const) and c.value:
            continue
        if isinstance(c, Const):
            return Const(value=False)
        if isinstance(c, All):
            flat.extend(c.children)
        else:
            flat.append(c)
    if not flat:
        return Const(value=True)
    if len(flat) == 1:
        return flat[0]
    return All(children=tuple(flat))


def any_of(children: list[Pred] | tuple[Pred, ...]) -> Pred:
    flat: list[Pred] = []
    for c in children:
        if isinstance(c, Const) and not c.value:
            continue
        if isinstance(c, Const):
            return Const(value=True)
        if isinstance(c, Any):
            flat.extend(c.children)
        else:
            flat.append(c)
    if not flat:
        return Const(value=False)
    if len(flat) == 1:
        return flat[0]
    return Any(children=tuple(flat))


def negate(p: Pred) -> Pred:
    if isinstance(p, Const):
        return Const(value=not p.value)
    if isinstance(p, Not):
        return p.child
    return Not(child=p)


def normalize(p: Pred) -> Pred:
    """Negation normal form; flattened and deduplicated ``All``/``Any``; idempotent."""
    return _nnf(p, negated=False)


def _nnf(p: Pred, negated: bool) -> Pred:
    if isinstance(p, Not):
        return _nnf(p.child, not negated)
    if isinstance(p, All | Any):
        children = [_nnf(c, negated) for c in p.children]
        conj = isinstance(p, All) != negated
        return _flatten(children, conj)
    if isinstance(p, Const):
        return Const(value=p.value != negated)
    return Not(child=p) if negated else p


def _flatten(children: list[Pred], conj: bool) -> Pred:
    flat: list[Pred] = []
    seen: set[Pred] = set()
    for c in children:
        parts = c.children if isinstance(c, All if conj else Any) else (c,)
        for part in parts:
            if isinstance(part, Const):
                if part.value == conj:
                    continue
                return Const(value=not conj)
            if part not in seen:
                seen.add(part)
                flat.append(part)
    if not flat:
        return Const(value=conj)
    if len(flat) == 1:
        return flat[0]
    return All(children=tuple(flat)) if conj else Any(children=tuple(flat))


def rename_var(p: Pred, mapping: dict[str | None, str | None]) -> Pred:
    """Rewrite the event-variable part of every field reference."""

    def qf(f: QField) -> QField:
        return (mapping.get(f[0], f[0]), f[1])

    if isinstance(p, LEAF_TYPES):
        return _replace(p, field=qf(p.field))
    if isinstance(p, Exists):
        return Exists(field=qf(p.field))
    if isinstance(p, Unknown):
        return Unknown(label=p.label, raw=p.raw, fields=tuple(qf(f) for f in p.fields))
    if isinstance(p, Not):
        return Not(child=rename_var(p.child, mapping))
    if isinstance(p, All):
        return All(children=tuple(rename_var(c, mapping) for c in p.children))
    if isinstance(p, Any):
        return Any(children=tuple(rename_var(c, mapping) for c in p.children))
    return p


def _replace(leaf: Leaf, **changes: object) -> Pred:
    import dataclasses

    return dataclasses.replace(leaf, **changes)  # type: ignore[return-value]
