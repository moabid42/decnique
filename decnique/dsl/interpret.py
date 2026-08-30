"""Concrete-event evaluation of DSL predicates (the naive oracle of plan §7.2).

An *event* is a mapping from event-model field names to values (``method``,
``principal``, ``caller_ip``, ``granted``, ...).  Raw UDM fields live under
``event["udm"]`` keyed by UDM path; tags under ``event["tags"]``.  A repeated field
may hold a list.  Evaluation is three-valued: ``True`` / ``False`` / ``None`` (unknown,
from ``Unknown`` atoms, absent reference lists, or - in *partial* mode - fields the
caller did not supply).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any as AnyT

from decnique.dsl.ast import Detection
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
    Like,
    Not,
    Pred,
    QField,
    Regex,
    StrFn,
    Unknown,
    referenced_fields,
)
from decnique.model.trace import TraceSpec

Event = Mapping[str, AnyT]
RefLists = Mapping[str, Sequence[str]]
Tri = bool | None

_MISSING = object()


def field_value(event: Event, qf: QField) -> object:
    """Value of a field in a concrete event, or ``_MISSING``.  The event variable is ignored."""
    _, path = qf
    if ef.is_udm(path):
        udm = event.get("udm") or {}
        return udm.get(ef.udm_path(path), _MISSING)
    if path.startswith(ef.TAG_PREFIX):
        tags = event.get("tags") or {}
        return tags.get(path[len(ef.TAG_PREFIX) :], _MISSING)
    return event.get(path, _MISSING)


def evaluate(
    p: Pred, event: Event, *, partial: bool = False, ref_lists: RefLists | None = None
) -> Tri:
    """Three-valued evaluation of ``p`` on ``event``.

    ``partial=True`` means the event is a partial description: an absent field yields
    ``None`` (could be anything) instead of ``False``.  Used by :func:`admits`.
    """
    if isinstance(p, Const):
        return p.value
    if isinstance(p, Unknown):
        return None
    if isinstance(p, Not):
        r = evaluate(p.child, event, partial=partial, ref_lists=ref_lists)
        return None if r is None else not r
    if isinstance(p, All):
        return _fold(
            [evaluate(c, event, partial=partial, ref_lists=ref_lists) for c in p.children],
            conj=True,
        )
    if isinstance(p, Any):
        return _fold(
            [evaluate(c, event, partial=partial, ref_lists=ref_lists) for c in p.children],
            conj=False,
        )
    raw = field_value(event, p.field)
    if isinstance(p, Exists):
        if raw is _MISSING:
            return None if partial else False
        return raw is not None
    if raw is _MISSING or raw is None:
        return None if partial else False
    values = list(raw) if isinstance(raw, list | tuple | set | frozenset) else [raw]
    results = [_leaf(p, v, ref_lists) for v in values]
    if not results:
        return False
    return _fold(results, conj=p.quant == "all")


def _fold(results: list[Tri], conj: bool) -> Tri:
    if conj:
        if any(r is False for r in results):
            return False
        return None if any(r is None for r in results) else True
    if any(r is True for r in results):
        return True
    return None if any(r is None for r in results) else False


def _norm(v: object, nocase: bool) -> object:
    if isinstance(v, str) and nocase:
        return v.lower()
    return v


def glob_to_regex(pattern: str) -> str:
    """The SIEM wildcard language: ``*`` any run, ``?`` one character, a backslash escapes the
    next character (``\\*`` is a literal star).  Nothing else is special — unlike
    :mod:`fnmatch`, ``[`` is an ordinary character (``projects/[x]/*``)."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def glob_match(value: str, pattern: str, nocase: bool = False) -> bool:
    flags = re.IGNORECASE | re.S if nocase else re.S
    return re.fullmatch(glob_to_regex(pattern), value, flags) is not None


def glob_unescape(pattern: str) -> str:
    """The literal a glob without wildcards denotes (``foo\\*`` → ``foo*``)."""
    return re.sub(r"\\(.)", r"\1", pattern)


def glob_has_wildcard(pattern: str) -> bool:
    return re.search(r"(?<!\\)(?:\\\\)*[*?]", pattern) is not None


def _leaf(p: Pred, v: object, ref_lists: RefLists | None) -> Tri:
    if isinstance(p, Cmp):
        return _cmp(p.op, v, p.value, p.nocase)
    if isinstance(p, Like):
        return glob_match(str(v), p.pattern, p.nocase)
    if isinstance(p, Regex):
        try:
            flags = re.IGNORECASE if p.nocase else 0
            return re.search(p.pattern, str(v), flags) is not None
        except re.error:
            return None
    if isinstance(p, StrFn):
        s, t = str(_norm(v, p.nocase)), str(_norm(p.value, p.nocase))
        if p.fn == "startswith":
            return s.startswith(t)
        if p.fn == "endswith":
            return s.endswith(t)
        return t in s
    if isinstance(p, In):
        return any(_cmp("=", v, x, p.nocase) for x in p.values)
    if isinstance(p, InCidr):
        try:
            addr = ipaddress.ip_address(str(v))
        except ValueError:
            return False
        for c in p.cidrs:
            try:
                if addr in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False
    if isinstance(p, InList):
        if ref_lists is None or p.list_name not in ref_lists:
            return None
        entries = ref_lists[p.list_name]
        if p.kind == "regex":
            return any(re.search(e, str(v), re.IGNORECASE if p.nocase else 0) for e in entries)
        if p.kind == "cidr":
            return _leaf(InCidr(field=p.field, cidrs=tuple(entries)), v, None)
        return any(_cmp("=", v, e, p.nocase) for e in entries)
    return None


def _cmp(op: str, left: object, right: object, nocase: bool) -> bool:
    if isinstance(right, bool) or isinstance(left, bool):
        l_, r_ = _as_bool(left), _as_bool(right)
        return (l_ == r_) if op == "=" else (l_ != r_) if op == "!=" else False
    if isinstance(right, int) and not isinstance(left, int):
        try:
            left = int(str(left))
        except ValueError:
            return op == "!="
    if isinstance(left, int) and isinstance(right, int):
        return _ordered(op, left, right)
    l_s, r_s = str(_norm(left, nocase)), str(_norm(right, nocase))
    return _ordered(op, l_s, r_s)


def _ordered(op: str, a: AnyT, b: AnyT) -> bool:
    return {
        "=": a == b,
        "!=": a != b,
        "<": a < b,
        "<=": a <= b,
        ">": a > b,
        ">=": a >= b,
    }[op]


def _as_bool(v: object) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return {"true": True, "false": False}.get(v.lower())
    if isinstance(v, int):
        return bool(v)
    return None


# --- rule-level questions ---------------------------------------------------------------


def observes(d: Detection, event: Event, *, ref_lists: RefLists | None = None) -> Tri:
    """``Observes(R, e)`` of plan §3.4: some event variable's predicate accepts ``e``,
    with the zero-value guard (every referenced field must exist unless
    ``allow_zero_values``)."""
    results: list[Tri] = []
    for ev in d.spec.events:
        pred = ev.pred
        if not d.spec.options.allow_zero_values:
            for var, path in referenced_fields(pred):
                if var not in (None, ev.name):
                    continue
                raw = field_value(event, (var, path))
                if raw is _MISSING or raw is None:
                    results.append(False)
                    break
            else:
                results.append(evaluate(pred, event, ref_lists=ref_lists))
        else:
            results.append(evaluate(pred, event, ref_lists=ref_lists))
    return _fold(results, conj=False)


def admits(
    d: Detection,
    method: str,
    *,
    service: str | None = None,
    permissions: Sequence[str] = (),
    var: str | None = None,
) -> bool:
    """``admits(v, method)`` of plan §5.11: can an event with this method satisfy the
    variable's method-level leaves?  Non-method leaves are treated as unknown, so the
    answer is an over-approximation ("could involve") and ``True`` for variables that
    do not constrain the method at all."""
    partial: dict[str, object] = {"method": method}
    if service is not None:
        partial["service"] = service
    if permissions:
        partial["permission"] = list(permissions)
    vars_ = [d.spec.event(var)] if var else list(d.spec.events)
    return any(evaluate(_method_only(ev.pred), partial, partial=True) is not False for ev in vars_)


def _method_only(p: Pred) -> Pred:
    """Replace every leaf that is not on a method-level field by an Unknown atom."""
    if isinstance(p, Not):
        return Not(child=_method_only(p.child))
    if isinstance(p, All):
        return All(children=tuple(_method_only(c) for c in p.children))
    if isinstance(p, Any):
        return Any(children=tuple(_method_only(c) for c in p.children))
    if isinstance(p, Const | Unknown):
        return p
    if p.field[1] in ef.METHOD_LEVEL_FIELDS:
        return p
    return Unknown(label="non_method_leaf", fields=(p.field,))


def admitted_methods(d: Detection, methods: Sequence[str], **kw: AnyT) -> tuple[str, ...]:
    return tuple(m for m in methods if admits(d, m, **kw))


def spec_methods_literal(spec: TraceSpec) -> frozenset[str]:
    """Method names mentioned literally (``=`` / ``in``) anywhere in the spec; a cheap
    prefilter, not a semantics."""
    out: set[str] = set()

    def walk(p: Pred) -> None:
        if (
            isinstance(p, Cmp)
            and p.field[1] == "method"
            and p.op == "="
            and isinstance(p.value, str)
        ):
            out.add(p.value)
        elif isinstance(p, In) and p.field[1] == "method":
            out.update(str(v) for v in p.values)
        elif isinstance(p, Not):
            walk(p.child)
        elif isinstance(p, All | Any):
            for c in p.children:
                walk(c)

    for ev in spec.events:
        walk(ev.pred)
    return frozenset(out)
