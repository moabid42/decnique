"""AST -> canonical DSL text (plan §5.10, `parse ∘ format == id`)."""

from __future__ import annotations

from decnique.dsl.ast import Bundle, Candidate, Check, Detection, Item, MetaValue, Ruleset
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
)
from decnique.model.trace import (
    AggBin,
    AggCall,
    AggCmp,
    AggConst,
    AggExpr,
    AggIf,
    AggRef,
    CAnd,
    CNot,
    CondExpr,
    COr,
    Count,
    CTrue,
    TraceSpec,
)

_IND = "  "


def quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def duration(seconds: int) -> str:
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds and seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def literal(v: MetaValue) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    return quote(v)


def qfield(f: QField) -> str:
    var, path = f
    if ef.is_udm(path):
        inner = f"udm({quote(ef.udm_path(path))})"
        return f"{var}.{inner}" if var else inner
    return f"{var}.{path}" if var else path


# --- predicates -----------------------------------------------------------------------


def pred(p: Pred) -> str:
    return _pred(p, 0)


_PREC = {"or": 1, "and": 2, "not": 3, "atom": 4}


def _wrap(text: str, inner: int, outer: int) -> str:
    return f"({text})" if inner < outer else text


def _pred(p: Pred, outer: int) -> str:
    if isinstance(p, Any):
        return _wrap(" or ".join(_pred(c, _PREC["or"]) for c in p.children), _PREC["or"], outer)
    if isinstance(p, All):
        return _wrap(" and ".join(_pred(c, _PREC["and"]) for c in p.children), _PREC["and"], outer)
    if isinstance(p, Not):
        if isinstance(p.child, Exists):
            return f"{qfield(p.child.field)} missing"
        return _wrap("not " + _pred(p.child, _PREC["not"]), _PREC["not"], outer)
    if isinstance(p, Const):
        return "true" if p.value else "false"
    if isinstance(p, Unknown):
        return f"unknown({quote(p.label)})"
    if isinstance(p, Exists):
        return f"{qfield(p.field)} exists"
    prefix = f"{p.quant} " if p.quant else ""
    suffix = " nocase" if p.nocase else ""
    f = qfield(p.field)
    if isinstance(p, Cmp):
        return f"{prefix}{f} {p.op} {literal(p.value)}{suffix}"
    if isinstance(p, Like):
        return f"{prefix}{f} like {quote(p.pattern)}{suffix}"
    if isinstance(p, Regex):
        return f"{prefix}{f} matches {quote(p.pattern)}{suffix}"
    if isinstance(p, StrFn):
        return f"{prefix}{f} {p.fn} {quote(p.value)}{suffix}"
    if isinstance(p, In):
        return f"{prefix}{f} in [{', '.join(literal(v) for v in p.values)}]{suffix}"
    if isinstance(p, InCidr):
        return f"{prefix}{f} in cidr [{', '.join(quote(c) for c in p.cidrs)}]"
    if isinstance(p, InList):
        kind = "" if p.kind == "string" else p.kind + " "
        return f"{prefix}{f} in {kind}%{p.list_name}{suffix}"
    raise TypeError(f"cannot format {p!r}")


# --- aggregates and conditions ---------------------------------------------------------


def agg(a: AggExpr) -> str:
    if isinstance(a, AggConst):
        return str(a.value)
    if isinstance(a, AggRef):
        return a.name
    if isinstance(a, AggCall):
        return f"{a.fn}({qfield(a.arg) if a.arg else ''})"
    if isinstance(a, AggIf):
        return f"if({pred(a.cond)}, {agg(a.then)}, {agg(a.else_)})"
    if isinstance(a, AggBin):
        left = agg(a.left)
        if a.op in {"+", "-"}:
            right = agg(a.right)
            if isinstance(a.right, AggBin) and a.right.op in {"+", "-"}:
                right = f"({right})"
            return f"{left} {a.op} {right}"
        if isinstance(a.left, AggBin) and a.left.op in {"+", "-"}:
            left = f"({left})"
        return f"{left} {a.op} {agg(a.right)}"
    raise TypeError(f"cannot format {a!r}")


def cond(c: CondExpr) -> str:
    return _cond(c, 0)


def _cond(c: CondExpr, outer: int) -> str:
    if isinstance(c, COr):
        return _wrap(" or ".join(_cond(x, 1) for x in c.children), 1, outer)
    if isinstance(c, CAnd):
        return _wrap(" and ".join(_cond(x, 2) for x in c.children), 2, outer)
    if isinstance(c, CNot):
        return _wrap("not " + _cond(c.child, 3), 3, outer)
    if isinstance(c, Count):
        return f"#{c.var}" if c.op == ">=" and c.n == 1 else f"#{c.var} {c.op} {c.n}"
    if isinstance(c, AggCmp):
        return f"{c.name} {c.op} {c.n}"
    if isinstance(c, CTrue):
        return "#__true__"
    raise TypeError(f"cannot format {c!r}")


# --- items ----------------------------------------------------------------------------


def _meta(meta: dict[str, MetaValue], ind: str) -> list[str]:
    if not meta:
        return []
    body = "  ".join(f"{k} = {literal(v)}" for k, v in meta.items())
    return [f"{ind}meta {{ {body} }}"]


def detection(d: Detection) -> str:
    lines = [f"detection {d.id} {{"]
    lines += _meta(d.meta, _IND)
    lines += _spec(d.spec)
    lines.append("}")
    return "\n".join(lines)


def _spec(spec: TraceSpec) -> list[str]:
    lines: list[str] = []
    if spec.is_single_event and spec.events[0].name == "e":
        lines.append(f"{_IND}event {pred(spec.events[0].pred)}")
    else:
        lines.append(f"{_IND}events {{")
        for ev in spec.events:
            lines.append(f"{_IND * 2}{ev.name}: {pred(ev.pred)}")
        lines.append(f"{_IND}}}")
    if spec.joins:
        body = "   ".join(f"{qfield(j.left)} = {qfield(j.right)}" for j in spec.joins)
        lines.append(f"{_IND}join {{ {body} }}")
    if spec.group_by:
        lines.append(f"{_IND}group by " + ", ".join(qfield(q) for q in spec.group_by))
    if spec.window:
        w = f"{_IND}window {duration(spec.window.seconds)}"
        if spec.window.anchor:
            w += f" {spec.window.side} {spec.window.anchor}"
        lines.append(w)
    if spec.order:
        lines.append(f"{_IND}order " + " < ".join(spec.order))
    if spec.aggregates:
        body = "   ".join(f"{n} = {agg(a)}" for n, a in spec.aggregates)
        lines.append(f"{_IND}aggregates {{ {body} }}")
    default = (
        Count(spec.events[0].name, ">=", 1)
        if len(spec.events) == 1
        else CAnd(tuple(Count(e.name, ">=", 1) for e in spec.events))
    )
    if spec.condition != default and not isinstance(spec.condition, CTrue):
        lines.append(f"{_IND}condition {cond(spec.condition)}")
    opts: dict[str, MetaValue] = {}
    if spec.options.allow_zero_values:
        opts["allow_zero_values"] = True
    opts.update(dict(spec.options.extra))
    if opts:
        body = "  ".join(f"{k} = {literal(v)}" for k, v in opts.items())
        lines.append(f"{_IND}options {{ {body} }}")
    return lines


def candidate(c: Candidate) -> str:
    lines = [f"candidate {c.id} {{"]
    lines += _meta(c.meta, _IND)
    if c.actor is not None:
        lines.append(f"{_IND}actor {pred(c.actor)}")
    lines.append(f"{_IND}required {{")
    for r in c.required:
        lines.append(f"{_IND * 2}{r.permission}" + (f" on {pred(r.where)}" if r.where else ""))
    lines.append(f"{_IND}}}")
    lines.append(f"{_IND}footprint {{")
    for s in c.footprint.steps:
        parts = [f"{_IND * 2}{s.id}: {quote(s.method)}"]
        if s.repeat != 1:
            parts.append(f"repeat {s.repeat}")
        if s.within_seconds is not None:
            parts.append(f"within {duration(s.within_seconds)}")
        if s.distinct:
            parts.append("distinct " + ", ".join(qfield(q) for q in s.distinct))
        if s.where is not None:
            parts.append(f"where {pred(s.where)}")
        lines.append(" ".join(parts))
    if c.footprint.order:
        lines.append(f"{_IND * 2}order " + " < ".join(c.footprint.order))
    if c.footprint.span_seconds is not None:
        lines.append(f"{_IND * 2}span {duration(c.footprint.span_seconds)}")
    lines.append(f"{_IND}}}")
    if c.context is not None:
        lines.append(f"{_IND}context {pred(c.context)}")
    if c.share != ("principal",):
        lines.append(f"{_IND}share " + ", ".join(c.share))
    lines.append("}")
    return "\n".join(lines)


def check(c: Check) -> str:
    lines = [f"check {c.id} {{", f"{_IND}type {c.type}"]
    for key, val in c.params.items():
        if key in {"event", "allowed"}:
            lines.append(f"{_IND}{key} {pred(val)}")  # type: ignore[arg-type]
        elif key in {"permissions", "resource"}:
            lines.append(f"{_IND}{key} like {quote(str(val))}")
        elif key in {"rules", "scope"}:
            lines.append(f"{_IND}{key} [" + ", ".join(val) + "]")  # type: ignore[arg-type]
        else:
            lines.append(f"{_IND}{key} {val}")
    lines.append("}")
    return "\n".join(lines)


def ruleset(r: Ruleset) -> str:
    lines = [f"ruleset {r.id} {{"]
    lines += [f"{_IND}include {quote(i)}" for i in r.includes]
    lines += [f"{_IND}disable {d}" for d in sorted(r.disabled)]
    lines += [f"{_IND}enable {e}" for e in sorted(r.enabled)]
    lines.append("}")
    return "\n".join(lines)


def item(i: Item) -> str:
    if isinstance(i, Detection):
        return detection(i)
    if isinstance(i, Candidate):
        return candidate(i)
    if isinstance(i, Check):
        return check(i)
    return ruleset(i)


def bundle(b: Bundle) -> str:
    items: list[Item] = [*b.detections, *b.candidates, *b.checks, *b.rulesets]
    return "\n\n".join(item(i) for i in items) + ("\n" if items else "")
