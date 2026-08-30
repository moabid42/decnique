"""YARA-L rule -> DSL :class:`Detection` (plan §5.16, lowering steps 1-6).

Everything outside the supported subset lowers to an ``Unknown`` atom (or, for
condition atoms, is dropped and named in the provenance's ``unsupported`` list); the
result is then *approximate*, never silently wrong.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from decnique.dsl.ast import Detection, Provenance
from decnique.dsl.parser import duration_seconds
from decnique.frontends.secops import parser as y
from decnique.frontends.secops.udm_map import UdmMap, load_udm_map
from decnique.model.predicates import (
    Cmp,
    Const,
    InCidr,
    InList,
    Not,
    Pred,
    QField,
    Regex,
    StrFn,
    Unknown,
    all_of,
    any_of,
)
from decnique.model.trace import (
    AggCall,
    AggCmp,
    AggConst,
    AggExpr,
    CAnd,
    CNot,
    CondExpr,
    COr,
    Count,
    CTrue,
    CUnknown,
    EventVar,
    Join,
    RuleOptions,
    TraceSpec,
    Window,
)

_AGG_FNS = {"sum", "max", "min", "count", "count_distinct"}
_TIMESTAMP_FIELDS = {"metadata.event_timestamp.seconds", "metadata.event_timestamp"}
_META_KEEP = (
    "rule_id",
    "rule_name",
    "severity",
    "priority",
    "author",
    "description",
    "mitre_attack_tactic",
    "mitre_attack_technique",
    "mitre_attack_technique_id",
    "mitre_attack_url",
    "platform",
    "data_source",
    "type",
)


@dataclass
class _State:
    vars: list[str] = field(default_factory=list)
    preds: dict[str, list[Pred]] = field(default_factory=lambda: defaultdict(list))
    bindings: dict[str, list[QField]] = field(
        default_factory=lambda: defaultdict(list)
    )  # placeholder -> fields
    joins: list[Join] = field(default_factory=list)
    order: list[tuple[str, str]] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def var(self, name: str) -> None:
        if name not in self.vars:
            self.vars.append(name)


def lower_rule(rule: y.YaralRule, file: str, udm: UdmMap | None = None) -> Detection:
    udm = udm or load_udm_map()
    st = _State()
    for stmt in rule.events:
        _lower_stmt(stmt, st, udm)
    if not st.vars:
        # No event variable was recognised: we do not know what the rule tests, so it must not
        # become ``true`` (that would make it observe every event — honesty invariant #1).
        st.var("e")
        st.preds["e"].append(Unknown(label="secops:no_event_variable"))
        st.unsupported.append("events:no_event_variable")

    # placeholders occurring in several variables are joins (lowering step 2); the same
    # placeholder bound to two fields of ONE variable is a field-to-field equality the DSL
    # cannot express — it stays a don't-know on that variable rather than vanishing
    for ph, fields in st.bindings.items():
        by_var: dict[str, list] = defaultdict(list)
        for f in fields:
            by_var[f[0]].append(f)
        for var, same in by_var.items():
            if len({f[1] for f in same}) > 1 and var in st.vars:
                st.preds[var].append(Unknown(label="secops:same_event_equality", raw=f"${ph}"))
                st.unsupported.append(f"events:same_event_equality:${ph}")
        distinct_vars = {f[0] for f in fields}
        if len(distinct_vars) > 1:
            first = fields[0]
            for other in fields[1:]:
                if other[0] != first[0]:
                    st.joins.append(Join(first, other))
        _ = ph

    group_by: list[QField] = []
    window: Window | None = None
    if rule.match is not None:
        for ph in rule.match.placeholders:
            fields = st.bindings.get(ph)
            if fields:
                group_by.append(fields[0])
            elif ph in st.vars:
                st.unsupported.append(f"match:event_variable:{ph}")
            else:
                st.unsupported.append(f"match:unbound_placeholder:{ph}")
        if rule.match.window:
            try:
                secs = duration_seconds(rule.match.window)
                if rule.match.anchor and rule.match.anchor in st.vars:
                    window = Window(secs, rule.match.anchor, rule.match.side or "around")  # type: ignore[arg-type]
                else:
                    if rule.match.anchor:
                        st.unsupported.append(f"match:anchor:{rule.match.anchor}")
                    window = Window(secs)
            except ValueError:
                st.unsupported.append(f"match:window:{rule.match.window}")
        else:
            st.unsupported.append("match:no_window")

    aggregates: dict[str, AggExpr] = {}
    outcome_kinds: dict[str, str] = {}
    for oc in rule.outcomes:
        agg = _lower_outcome(oc, st, udm)
        if agg is not None:
            aggregates[oc.name] = agg
            outcome_kinds[oc.name] = "aggregate"
        else:
            outcome_kinds[oc.name] = "other"

    condition = _lower_condition(rule.condition, st, aggregates, outcome_kinds, udm)

    events = tuple(
        EventVar(v, all_of(st.preds.get(v, [])) if st.preds.get(v) else Const(value=True))
        for v in st.vars
    )
    order = tuple(_linearize(st.order, st.vars))
    allow_zero = bool(rule.options.get("allow_zero_values", False))
    extra = tuple(sorted((k, v) for k, v in rule.options.items() if k != "allow_zero_values"))
    spec = TraceSpec(
        events=events,
        joins=tuple(st.joins),
        group_by=tuple(group_by),
        window=window,
        order=order,
        aggregates=tuple(aggregates.items()),
        condition=condition,
        options=RuleOptions(allow_zero, extra),
    )
    meta = {k: v for k, v in rule.meta.items() if k in _META_KEEP}
    meta["source"] = "secops"
    return Detection(
        id=rule.name,
        spec=spec,
        meta=meta,
        source=Provenance(
            file=file,
            frontend="secops",
            line=rule.line,
            native_id=rule.meta.get("rule_id", rule.name),
            unsupported=tuple(dict.fromkeys(st.unsupported)),
            notes=tuple(st.notes),
        ),
    )


# --- events ----------------------------------------------------------------------------------


def _lower_stmt(e: y.Expr, st: _State, udm: UdmMap) -> None:
    if isinstance(e, y.RawStmt):
        st.unsupported.append(f"events:unparsed:{e.text[:60]}")
        target = st.vars[0] if st.vars else "e"
        st.var(target)
        st.preds[target].append(Unknown(label="secops:unparsed", raw=e.text))
        return
    vars_ = sorted(_vars_of(e))
    if len(vars_) == 1:
        st.var(vars_[0])
        st.preds[vars_[0]].append(_expr(e, vars_[0], st, udm))
        return
    if len(vars_) == 0:
        # placeholder-only or constant statement
        target = st.vars[0] if st.vars else "e"
        st.var(target)
        st.preds[target].append(_expr(e, target, st, udm))
        return
    # a top-level statement mentioning two variables: join / order / cross-variable compare
    for v in vars_:
        st.var(v)
    if (
        isinstance(e, y.Compare)
        and isinstance(e.left, y.FieldRef)
        and isinstance(e.right, y.FieldRef)
    ):
        lf, rf = e.left, e.right
        if e.op == "=" and lf.var != rf.var:
            st.joins.append(Join(udm.qfield(lf.var, lf.path), udm.qfield(rf.var, rf.path)))
            return
        if e.op in {"<", "<="} and lf.path in _TIMESTAMP_FIELDS and rf.path in _TIMESTAMP_FIELDS:
            st.order.append((lf.var, rf.var))
            return
        if e.op in {">", ">="} and lf.path in _TIMESTAMP_FIELDS and rf.path in _TIMESTAMP_FIELDS:
            st.order.append((rf.var, lf.var))
            return
    st.unsupported.append(f"events:cross_variable:{_render(e)[:60]}")
    st.preds[vars_[0]].append(
        Unknown(
            label="secops:cross_variable", raw=_render(e), fields=tuple((v, "udm:?") for v in vars_)
        )
    )


def _vars_of(e: y.Expr | y.Operand) -> set[str]:
    if isinstance(e, y.FieldRef):
        return {e.var}
    if isinstance(e, y.Call):
        return set().union(*(_vars_of(a) for a in e.args)) if e.args else set()
    if isinstance(e, y.Compare):
        return _vars_of(e.left) | _vars_of(e.right)
    if isinstance(e, y.InRef | y.Bare):
        return _vars_of(e.operand)
    if isinstance(e, y.FuncPred):
        return _vars_of(e.call)
    if isinstance(e, y.NotE):
        return _vars_of(e.child)
    if isinstance(e, y.AndE | y.OrE):
        return set().union(*(_vars_of(c) for c in e.children))
    return set()


def _expr(e: y.Expr, var: str, st: _State, udm: UdmMap) -> Pred:
    if isinstance(e, y.RawStmt):
        st.unsupported.append(f"events:unparsed:{e.text[:60]}")
        return Unknown(label="secops:unparsed", raw=e.text)
    if isinstance(e, y.NotE):
        return Not(child=_expr(e.child, var, st, udm))
    if isinstance(e, y.AndE):
        return all_of([_expr(c, var, st, udm) for c in e.children])
    if isinstance(e, y.OrE):
        return any_of([_expr(c, var, st, udm) for c in e.children])
    if isinstance(e, y.Compare):
        return _compare(e, var, st, udm)
    if isinstance(e, y.InRef):
        f = _field_of(e.operand, var, st, udm)
        if f is None:
            return _unk(st, "secops:in_ref_operand", _render(e))
        return InList(field=f, list_name=e.list_name, kind=e.kind, nocase=e.nocase, quant=e.quant)  # type: ignore[arg-type]
    if isinstance(e, y.FuncPred):
        return _func_pred(e.call, e.nocase, var, st, udm)
    if isinstance(e, y.Bare):
        if isinstance(e.operand, y.Placeholder | y.FieldRef):
            return Const(value=True)  # existence; the zero-value guard handles it
        return _unk(st, "secops:bare_operand", _render(e))
    return _unk(st, "secops:unsupported", _render(e))


def _compare(e: y.Compare, var: str, st: _State, udm: UdmMap) -> Pred:
    left, right = e.left, e.right
    # normalise "literal op field" to "field op literal"
    if not isinstance(left, y.FieldRef | y.Placeholder | y.Call) and isinstance(
        right, y.FieldRef | y.Placeholder | y.Call
    ):
        left, right = right, left
        flip = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}
        e = y.Compare(left, flip.get(e.op, e.op), right, e.nocase, e.quant)
    # placeholder binding: $e.f = $x
    if isinstance(right, y.Placeholder):
        if isinstance(left, y.FieldRef) and e.op == "=":
            st.bindings[right.name].append(udm.qfield(left.var, left.path))
            return Const(value=True)
        if isinstance(left, y.Placeholder):
            return _unk(st, "secops:placeholder_compare", _render(e))
        return _unk(st, "secops:placeholder_op", _render(e))
    if isinstance(left, y.Placeholder):
        # $x = "value": constrain every field the placeholder is bound to so far
        fields = st.bindings.get(left.name, [])
        if fields and isinstance(right, y.Str | y.Num | y.Bool):
            return all_of(
                [Cmp(field=f, op=e.op, value=_val(right), nocase=e.nocase) for f in fields]
            )  # type: ignore[arg-type]
        return _unk(st, "secops:placeholder_literal", _render(e))
    nocase = e.nocase
    f: QField | None
    if isinstance(left, y.Call):
        fn = left.fn.lower()
        if (
            fn in {"strings.to_lower", "strings.to_upper"}
            and len(left.args) == 1
            and isinstance(left.args[0], y.FieldRef)
        ):
            nocase = True
            left = left.args[0]
        else:
            return _unk(st, f"secops:function:{left.fn}", _render(e))
    if not isinstance(left, y.FieldRef):
        return _unk(st, "secops:compare_operand", _render(e))
    if isinstance(right, y.Rx):
        f = udm.qfield(left.var, left.path)
        rx: Pred = Regex(field=f, pattern=right.pattern, nocase=nocase, quant=e.quant)
        if e.op == "=":
            return rx
        if e.op == "!=":
            return Not(child=rx)
        return _unk(st, "secops:regex_op", _render(e))
    if isinstance(right, y.FieldRef):
        if right.var == left.var:
            return _unk(st, "secops:same_var_field_compare", _render(e))
        return _unk(st, "secops:cross_variable", _render(e))
    if isinstance(right, y.Call):
        return _unk(st, f"secops:function:{right.fn}", _render(e))
    if isinstance(right, y.Str | y.Num | y.Bool):
        _note_unverified(left.path, st, udm)
        return _with_quant(udm.compare(left.var, left.path, e.op, _val(right), nocase), e.quant)
    return _unk(st, "secops:compare", _render(e))


def _with_quant(p: Pred, quant: str | None) -> Pred:
    if quant and isinstance(p, Cmp):
        import dataclasses

        return dataclasses.replace(p, quant=quant)
    return p


def _unwrap_case(operand):  # type: ignore[no-untyped-def]
    """``strings.to_lower($f)`` / ``strings.to_upper($f)`` → ``($f, nocase=True)``; anything else
    passes through unchanged.  Rules routinely lowercase a field before matching it against a
    lowercase literal (``strings.contains(strings.to_lower($f), "x")``); unwrapping the case call
    turns that into a plain case-insensitive match the model represents exactly."""
    if (
        isinstance(operand, y.Call)
        and operand.fn.lower() in {"strings.to_lower", "strings.to_upper"}
        and len(operand.args) == 1
        and isinstance(operand.args[0], y.FieldRef)
    ):
        return operand.args[0], True
    return operand, False


def _func_pred(call: y.Call, nocase: bool, var: str, st: _State, udm: UdmMap) -> Pred:
    fn = call.fn.lower()
    args = list(call.args)
    if args:  # a case-normalized field argument becomes a case-insensitive match on the field
        inner, folded = _unwrap_case(args[0])
        if folded:
            args[0] = inner
            nocase = True
    if (
        fn == "re.regex"
        and len(args) == 2
        and isinstance(args[0], y.FieldRef)
        and isinstance(args[1], y.Str)
    ):
        return Regex(
            field=udm.qfield(args[0].var, args[0].path), pattern=args[1].value, nocase=nocase
        )
    if (
        fn == "net.ip_in_range_cidr"
        and len(args) == 2
        and isinstance(args[0], y.FieldRef)
        and isinstance(args[1], y.Str)
    ):
        return InCidr(field=udm.qfield(args[0].var, args[0].path), cidrs=(args[1].value,))
    if (
        fn in {"strings.contains", "strings.starts_with", "strings.ends_with"}
        and len(args) == 2
        and isinstance(args[0], y.FieldRef)
        and isinstance(args[1], y.Str)
    ):
        kind = {
            "strings.contains": "contains",
            "strings.starts_with": "startswith",
            "strings.ends_with": "endswith",
        }[fn]
        return StrFn(
            field=udm.qfield(args[0].var, args[0].path), fn=kind, value=args[1].value, nocase=nocase
        )  # type: ignore[arg-type]
    return _unk(
        st,
        f"secops:function:{call.fn}",
        _render(y.FuncPred(call, nocase)),
        fields=tuple(udm.qfield(a.var, a.path) for a in args if isinstance(a, y.FieldRef)),
    )


def _field_of(op: y.Operand, var: str, st: _State, udm: UdmMap) -> QField | None:
    if isinstance(op, y.FieldRef):
        return udm.qfield(op.var, op.path)
    if isinstance(op, y.Placeholder):
        fields = st.bindings.get(op.name)
        return fields[0] if fields else None
    if (
        isinstance(op, y.Call)
        and op.fn.lower() in {"strings.to_lower", "strings.to_upper"}
        and op.args
        and isinstance(op.args[0], y.FieldRef)
    ):
        return udm.qfield(op.args[0].var, op.args[0].path)
    return None


def _note_unverified(path: str, st: _State, udm: UdmMap) -> None:
    row = udm.lookup(path)
    if row is not None and not row.verified:
        note = f"udm_row_unverified:{path}"
        if note not in st.notes:
            st.notes.append(note)


def _unk(st: _State, label: str, raw: str, fields: tuple[QField, ...] = ()) -> Pred:
    st.unsupported.append(label)
    return Unknown(label=label, raw=raw, fields=fields)


def _val(o: y.Str | y.Num | y.Bool) -> str | int | bool:
    return o.value


def _render(e: object) -> str:
    return re.sub(r"\s+", " ", repr(e))[:200]


# --- outcomes ----------------------------------------------------------------------------------


def _lower_outcome(oc: y.Outcome, st: _State, udm: UdmMap) -> AggExpr | None:
    expr = oc.expr
    if isinstance(expr, y.RawStmt):
        return None
    return _agg(expr, st, udm)


def _agg(o: y.Operand, st: _State, udm: UdmMap) -> AggExpr | None:
    if isinstance(o, y.Num):
        return AggConst(o.value)
    if isinstance(o, y.Call):
        fn = o.fn.lower()
        if fn in _AGG_FNS:
            if len(o.args) == 1 and isinstance(o.args[0], y.Num) and fn in {"max", "min", "sum"}:
                return AggConst(o.args[0].value)
            if len(o.args) == 1 and isinstance(o.args[0], y.FieldRef):
                return AggCall(fn, udm.qfield(o.args[0].var, o.args[0].path))  # type: ignore[arg-type]
            if len(o.args) == 1 and isinstance(o.args[0], y.Placeholder):
                fields = st.bindings.get(o.args[0].name)
                if fields:
                    return AggCall(fn, fields[0])  # type: ignore[arg-type]
            if fn == "count" and not o.args:
                return AggCall("count", None)
            return None
        if fn in {"+", "-", "*", "/"} and len(o.args) == 2:
            from decnique.model.trace import AggBin

            left, right = _agg(o.args[0], st, udm), _agg(o.args[1], st, udm)
            if left is None or right is None:
                return None
            if fn in {"*", "/"} and not isinstance(right, AggConst):
                return None
            return AggBin(fn, left, right)  # type: ignore[arg-type]
    return None


# --- conditions --------------------------------------------------------------------------------


def _lower_condition(
    c: y.Cond | None,
    st: _State,
    aggregates: dict[str, AggExpr],
    outcome_kinds: dict[str, str],
    udm: UdmMap,
) -> CondExpr:
    if c is None:
        return (
            CAnd(tuple(Count(v, ">=", 1) for v in st.vars))
            if len(st.vars) > 1
            else Count(st.vars[0], ">=", 1)
        )
    out = _cond(c, st, aggregates, outcome_kinds)
    # An untranslatable condition must not become "always true" — that would broaden the rule
    # (e.g. drop a `#e > 3` threshold) and let a proof lean on it.
    return out if out is not None else CUnknown("secops:condition")


def _cond(
    c: y.Cond, st: _State, aggregates: dict[str, AggExpr], kinds: dict[str, str]
) -> CondExpr | None:
    if isinstance(c, y.RawStmt):
        st.unsupported.append(f"condition:unparsed:{c.text[:60]}")
        return None
    if isinstance(c, y.CondNot):
        inner = _cond(c.child, st, aggregates, kinds)
        return CNot(inner) if inner is not None else None
    if isinstance(c, y.CondAnd | y.CondOr):
        lowered = [_cond(k, st, aggregates, kinds) for k in c.children]
        if any(x is None for x in lowered):
            # keep the understood parts, and an explicit don't-know for the rest: dropping a
            # conjunct would make the rule fire more often than it really does
            st.unsupported.append("condition:partially_lowered")
        parts = [x if x is not None else CUnknown("secops:condition_part") for x in lowered]
        if len(parts) == 1:
            return parts[0]
        return CAnd(tuple(parts)) if isinstance(c, y.CondAnd) else COr(tuple(parts))
    if isinstance(c, y.CountAtom):
        if c.name in st.vars:
            return Count(c.name, c.op, c.n)
        fields = st.bindings.get(c.name)
        if fields:
            # #$placeholder counts distinct values of the bound field
            name = f"__count_{c.name}"
            aggregates.setdefault(name, AggCall("count_distinct", fields[0]))
            return AggCmp(name, c.op, c.n)
        st.unsupported.append(f"condition:unknown_count:{c.name}")
        return None
    if isinstance(c, y.VarAtom):
        if c.op is None:
            if c.name in st.vars:
                return Count(c.name, ">=", 1)
            st.unsupported.append(f"condition:unknown_variable:{c.name}")
            return None
        if c.name in aggregates and isinstance(c.value, int):
            return AggCmp(c.name, c.op, c.value)
        if c.name in st.vars and isinstance(c.value, int):
            return Count(c.name, c.op, c.value)
        label = (
            "condition:non_aggregate_outcome"
            if kinds.get(c.name) == "other"
            else "condition:unknown_atom"
        )
        st.unsupported.append(f"{label}:{c.name}")
        return None
    return None


def _linearize(pairs: list[tuple[str, str]], vars_: list[str]) -> list[str]:
    """Topological order of event variables from ``a < b`` constraints; empty if none or cyclic."""
    if not pairs:
        return []
    order: list[str] = []
    remaining = {v for p in pairs for v in p}
    edges = set(pairs)
    while remaining:
        roots = sorted(v for v in remaining if not any(b == v for a, b in edges if a in remaining))
        if not roots:
            return []
        order.append(roots[0])
        remaining.remove(roots[0])
    return order
