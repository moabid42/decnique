"""Lark parse tree -> DSL AST, with name resolution and semantic checks (plan §5.10.1).

Every error carries ``file:line:col``.  The single-event sugar ``event <expr>`` is
desugared here to ``events { e: <expr> }`` with ``condition #e >= 1``; downstream
code only ever sees :class:`~decnique.model.trace.TraceSpec`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from lark import Lark, Token, Tree
from lark.exceptions import UnexpectedCharacters, UnexpectedInput, UnexpectedToken

from decnique.dsl.ast import (
    CHECK_MODES,
    CHECK_TYPES,
    Bundle,
    Candidate,
    Check,
    Detection,
    Footprint,
    Item,
    LoadIssue,
    MetaValue,
    Provenance,
    Required,
    Ruleset,
    Step,
)
from decnique.model import event_fields as ef
from decnique.model.predicates import (
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
    all_of,
    any_of,
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
    CUnknown,
    CondExpr,
    COr,
    Count,
    EventVar,
    Join,
    RuleOptions,
    TraceSpec,
    Window,
)

GRAMMAR_PATH = Path(__file__).with_name("grammar.lark")
DEFAULT_MAX_EVENTS = 16
SHAREABLE: frozenset[str] = frozenset(
    {"principal", "principal_type", "caller_ip", "user_agent", "project", "org", "folder"}
)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class DslError(ValueError):
    def __init__(self, file: str, line: int | None, col: int | None, message: str) -> None:
        self.file, self.line, self.col, self.message = file, line, col, message
        where = f"{file}:{line}:{col}" if line is not None else file
        super().__init__(f"{where}: {message}")


@dataclass(frozen=True, slots=True)
class ParseOptions:
    max_events: int = DEFAULT_MAX_EVENTS


_PARSER: Lark | None = None


def _lark() -> Lark:
    global _PARSER
    if _PARSER is None:
        _PARSER = Lark(
            GRAMMAR_PATH.read_text(encoding="utf-8"),
            parser="lalr",
            lexer="contextual",
            propagate_positions=True,
            start="start",
        )
    return _PARSER


def parse_text(text: str, file: str = "<string>", options: ParseOptions | None = None) -> Bundle:
    """Parse DSL source into a :class:`Bundle`.  Raises :class:`DslError` on the first error."""
    try:
        tree = _lark().parse(text)
    except UnexpectedToken as e:
        expected = ", ".join(sorted(_pretty_terminal(t) for t in e.expected)[:8])
        raise DslError(
            file,
            e.line,
            e.column,
            f"unexpected {_pretty_token(e.token)}; expected one of {expected}",
        ) from None
    except UnexpectedCharacters as e:
        raise DslError(
            file, e.line, e.column, f"unexpected character {text[e.pos_in_stream]!r}"
        ) from None
    except UnexpectedInput as e:  # pragma: no cover - other lark errors
        raise DslError(file, getattr(e, "line", None), getattr(e, "column", None), str(e)) from None
    builder = _Builder(file, options or ParseOptions())
    items = [builder.item(child) for child in tree.children]
    return _bundle(items, builder.issues)


def parse_file(path: Path, options: ParseOptions | None = None) -> Bundle:
    return parse_text(Path(path).read_text(encoding="utf-8"), str(path), options)


def parse_expr(text: str, file: str = "<string>", vars_: Iterable[str] = ()) -> Pred:
    """Parse a bare matcher expression (used by tests and the CLI)."""
    bundle = parse_text(f"detection __expr__ {{ event {text} }}", file)
    return bundle.detections[0].spec.events[0].pred


def _bundle(items: list[Item], issues: list[LoadIssue]) -> Bundle:
    return Bundle(
        detections=tuple(i for i in items if isinstance(i, Detection)),
        candidates=tuple(i for i in items if isinstance(i, Candidate)),
        checks=tuple(i for i in items if isinstance(i, Check)),
        rulesets=tuple(i for i in items if isinstance(i, Ruleset)),
        issues=tuple(issues),
    )


def _pretty_terminal(name: str) -> str:
    return {
        "NAME": "identifier",
        "DOTTED": "dotted name",
        "STRING": "string",
        "NUMBER": "number",
        "DURATION": "duration",
        "REGEX": "regex",
        "$END": "end of input",
    }.get(name, name.lower().replace("__anon_", ""))


def _pretty_token(tok: Token) -> str:
    return "end of input" if tok.type == "$END" else repr(str(tok))


def unescape(s: str) -> str:
    """Decode a STRING token (surrounding quotes and backslash escapes).  Only ``\\\\``, ``\\"``,
    ``\\n`` and ``\\t`` are escapes; any other backslash is kept, so a regex or glob written
    as ``"\\d+"`` or ``"foo\\*"`` means what it says."""
    body = s[1:-1]
    return re.sub(
        r"\\(.)",
        lambda m: {"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(m.group(1), "\\" + m.group(1)),
        body,
    )


def unescape_regex(s: str) -> str:
    return s[1:-1].replace("\\/", "/")


def duration_seconds(tok: str) -> int:
    m = re.fullmatch(r"([0-9]+)(ms|s|m|h|d)", tok)
    assert m
    n, unit = int(m.group(1)), m.group(2)
    if unit == "ms":
        raise ValueError("sub-second durations are not supported")
    return n * _UNIT_SECONDS[unit]


class _Builder:
    def __init__(self, file: str, options: ParseOptions) -> None:
        self.file = file
        self.options = options
        self.issues: list[LoadIssue] = []

    # --- helpers ----------------------------------------------------------------------
    def err(self, node: Tree | Token, message: str) -> DslError:
        if isinstance(node, Token):
            return DslError(self.file, node.line, node.column, message)
        meta = node.meta
        return DslError(
            self.file, getattr(meta, "line", None), getattr(meta, "column", None), message
        )

    @staticmethod
    def sub(node: Tree, name: str) -> Tree | None:
        for c in node.children:
            if isinstance(c, Tree) and c.data == name:
                return c
        return None

    @staticmethod
    def subs(node: Tree, name: str) -> list[Tree]:
        return [c for c in node.children if isinstance(c, Tree) and c.data == name]

    @staticmethod
    def qfields(node: Tree) -> list[Tree]:
        return [c for c in node.children if isinstance(c, Tree) and c.data.startswith("qf_")]

    @staticmethod
    def tokens(node: Tree, type_: str) -> list[Token]:
        return [c for c in node.children if isinstance(c, Token) and c.type == type_]

    def literal(self, node: Tree) -> MetaValue:
        child = node.children[0]
        if isinstance(child, Tree):
            return child.data == "true"
        if child.type == "STRING":
            return unescape(child)
        if child.type == "NUMBER":
            return int(child)
        return str(child)  # DURATION kept as text in meta

    def value(self, node: Tree) -> str | int | bool:
        return self.literal(node)  # type: ignore[return-value]

    def meta(self, node: Tree | None) -> dict[str, MetaValue]:
        out: dict[str, MetaValue] = {}
        if node is None:
            return out
        for entry in self.subs(node, "meta_entry"):
            name = self.tokens(entry, "NAME")[0]
            out[str(name)] = self.literal(self.sub(entry, "literal"))  # type: ignore[arg-type]
        return out

    # --- items ------------------------------------------------------------------------
    def item(self, node: Tree) -> Item:
        return {
            "detection": self.detection,
            "candidate": self.candidate,
            "check": self.check,
            "ruleset": self.ruleset,
        }[node.data](node)

    # --- detections -------------------------------------------------------------------
    def detection(self, node: Tree) -> Detection:
        name = self.tokens(node, "NAME")[0]
        meta = self.meta(self.sub(node, "meta"))
        events_node = self.sub(node, "single_event") or self.sub(node, "multi_event")
        assert events_node is not None
        if events_node.data == "single_event":
            var_names = ["e"]
            exprs = [(Token("NAME", "e"), events_node.children[0])]
        else:
            exprs = []
            var_names = []
            for ev in self.subs(events_node, "event_var"):
                tok = self.tokens(ev, "NAME")[0]
                if str(tok) in var_names:
                    raise self.err(tok, f"duplicate event variable {tok!s}")
                var_names.append(str(tok))
                exprs.append((tok, ev.children[1]))
        scope = _Scope(self, tuple(var_names), implicit=events_node.data == "single_event")
        events = tuple(EventVar(str(tok), scope.expr(expr)) for tok, expr in exprs)
        joins = tuple(
            scope.join(j) for j in self.subs(self.sub(node, "join") or Tree("x", []), "join_eq")
        )
        gb_node = self.sub(node, "group_by")
        group_by = tuple(scope.qfield(q) for q in self.qfields(gb_node)) if gb_node else ()
        window = self.window(self.sub(node, "window"), var_names)
        order = self.order(self.sub(node, "order"), var_names, "event variable")
        aggregates = tuple(
            (str(self.tokens(a, "NAME")[0]), scope.agg(a.children[1]))
            for a in self.subs(self.sub(node, "aggregates") or Tree("x", []), "agg_def")
        )
        agg_names = [n for n, _ in aggregates]
        if len(set(agg_names)) != len(agg_names):
            raise self.err(self.sub(node, "aggregates") or node, "duplicate aggregate name")
        cond_node = self.sub(node, "condition")
        if cond_node is None:
            condition: CondExpr = (
                Count(var_names[0], ">=", 1)
                if len(var_names) == 1
                else CAnd(tuple(Count(v, ">=", 1) for v in var_names))
            )
        else:
            condition = self.cond(cond_node.children[0], var_names, agg_names)
        options = self.rule_options(self.sub(node, "options"))
        spec = TraceSpec(events, joins, group_by, window, order, aggregates, condition, options)
        return Detection(
            id=str(name),
            spec=spec,
            meta=meta,
            source=Provenance(file=self.file, frontend="dsl", line=name.line),
        )

    def window(self, node: Tree | None, var_names: list[str]) -> Window | None:
        if node is None:
            return None
        dur = self.tokens(node, "DURATION")[0]
        try:
            seconds = duration_seconds(str(dur))
        except ValueError as e:
            raise self.err(dur, str(e)) from None
        anchor = self.sub(node, "before") or self.sub(node, "after")
        if anchor is None:
            return Window(seconds)
        tok = self.tokens(anchor, "NAME")[0]
        if str(tok) not in var_names:
            raise self.err(tok, f"window anchor {tok!s} is not an event variable")
        return Window(seconds, str(tok), anchor.data)  # type: ignore[arg-type]

    def order(self, node: Tree | None, names: list[str], kind: str) -> tuple[str, ...]:
        if node is None:
            return ()
        out: list[str] = []
        for tok in self.tokens(node, "NAME"):
            if str(tok) not in names:
                raise self.err(tok, f"order refers to unknown {kind} {tok!s}")
            if str(tok) in out:
                raise self.err(tok, f"{tok!s} appears twice in order")
            out.append(str(tok))
        return tuple(out)

    def cond(self, node: Tree, var_names: list[str], agg_names: list[str]) -> CondExpr:
        if node.data in {"cor", "cand"}:
            cls = COr if node.data == "cor" else CAnd
            parts: list[CondExpr] = []
            for c in node.children:
                sub = self.cond(c, var_names, agg_names)
                parts.extend(sub.children if isinstance(sub, cls) else (sub,))
            return cls(tuple(parts))
        if node.data == "cnot":
            return CNot(self.cond(node.children[0], var_names, agg_names))
        if node.data == "cunknown":
            return CUnknown(unescape(str(node.children[0])))
        if node.data == "count_cmp":
            tok, op, n = node.children
            if str(tok) not in var_names:
                raise self.err(tok, f"#{tok!s}: unknown event variable")
            return Count(str(tok), _CMP[op.data], int(n))
        if node.data == "count_exists":
            tok = node.children[0]
            if str(tok) not in var_names:
                raise self.err(tok, f"#{tok!s}: unknown event variable")
            return Count(str(tok), ">=", 1)
        if node.data == "agg_cmp":
            tok, op, n = node.children
            if str(tok) not in agg_names:
                raise self.err(tok, f"condition refers to undefined aggregate {tok!s}")
            return AggCmp(str(tok), _CMP[op.data], int(n))
        raise self.err(node, f"unsupported condition node {node.data}")

    def rule_options(self, node: Tree | None) -> RuleOptions:
        entries = self.meta(node)
        allow_zero = bool(entries.pop("allow_zero_values", False))
        return RuleOptions(allow_zero_values=allow_zero, extra=tuple(sorted(entries.items())))

    # --- candidates -------------------------------------------------------------------
    def candidate(self, node: Tree) -> Candidate:
        name = self.tokens(node, "NAME")[0]
        meta = self.meta(self.sub(node, "meta"))
        plain = _Scope(self, (), implicit=True)
        actor_node = self.sub(node, "actor")
        actor = plain.expr(actor_node.children[0]) if actor_node else None
        required: list[Required] = []
        for req in self.subs(self.sub(node, "required"), "req"):  # type: ignore[arg-type]
            perm = self.tokens(req, "DOTTED")[0]
            where = plain.expr(req.children[1]) if len(req.children) > 1 else None
            required.append(Required(str(perm), where))
        fp = self.sub(node, "footprint")
        assert fp is not None
        steps: list[Step] = []
        step_ids: list[str] = []
        for st in self.subs(fp, "step"):
            sid = self.tokens(st, "NAME")[0]
            if str(sid) in step_ids:
                raise self.err(sid, f"duplicate step {sid!s}")
            step_ids.append(str(sid))
            method_node = self.sub(st, "method")
            assert method_node is not None
            mtok = method_node.children[0]
            method = unescape(mtok) if mtok.type == "STRING" else str(mtok)
            repeat, within, distinct, where = 1, None, (), None
            for opt in [
                c
                for c in st.children
                if isinstance(c, Tree) and c.data in {"repeat", "within", "distinct", "where"}
            ]:
                if opt.data == "repeat":
                    repeat = int(opt.children[0])
                    if repeat < 1:
                        raise self.err(opt, "repeat must be >= 1")
                elif opt.data == "within":
                    within = duration_seconds(str(opt.children[0]))
                elif opt.data == "distinct":
                    distinct = tuple(plain.qfield(q) for q in self.qfields(opt))
                else:
                    where = plain.expr(opt.children[0])
            steps.append(Step(str(sid), method, repeat, within, distinct, where))
        total = sum(s.repeat for s in steps)
        if total > self.options.max_events:
            raise self.err(
                fp,
                f"footprint needs {total} events, more than max_events = {self.options.max_events}",
            )
        order = self.order(self.sub(fp, "fp_order"), step_ids, "step")
        span_node = self.sub(fp, "span")
        span = duration_seconds(str(span_node.children[0])) if span_node else None
        ctx_node = self.sub(node, "context")
        context = plain.expr(ctx_node.children[0]) if ctx_node else None
        share_node = self.sub(node, "share")
        share: tuple[str, ...] = ("principal",)
        if share_node:
            names = []
            for tok in self.tokens(share_node, "NAME"):
                if str(tok) not in SHAREABLE:
                    raise self.err(
                        tok, f"{tok!s} is not shareable (shareable: {', '.join(sorted(SHAREABLE))})"
                    )
                names.append(str(tok))
            share = tuple(names)
        gains_node = self.sub(node, "gains")
        gains = tuple(dict.fromkeys(str(t) for t in self.tokens(gains_node, "DOTTED"))) if gains_node else ()
        return Candidate(
            id=str(name),
            required=tuple(required),
            footprint=Footprint(tuple(steps), order, span),
            meta=meta,
            actor=actor,
            context=context,
            share=share,
            gains=gains,
        )

    # --- checks -----------------------------------------------------------------------
    def check(self, node: Tree) -> Check:
        name = self.tokens(node, "NAME")[0]
        typename = self.sub(node, "typename") or self.sub(node, "candidate_type")
        assert typename is not None
        type_ = "candidate" if typename.data == "candidate_type" else str(typename.children[0])
        if type_ not in CHECK_TYPES:
            raise self.err(
                typename, f"unknown check type {type_!r}; one of {', '.join(CHECK_TYPES)}"
            )
        plain = _Scope(self, (), implicit=True)
        params: dict[str, object] = {}
        for opt in [c for c in node.children if isinstance(c, Tree) and c.data.startswith("co_")]:
            key = opt.data[3:]
            if key in {"event", "allowed"}:
                params[key] = plain.expr(opt.children[0])
            elif key in {"permissions", "resource"}:
                params[key] = unescape(opt.children[0])
            elif key == "permission":
                params[key] = str(opt.children[0])
            elif key in {"rules", "scope"}:
                params[key] = tuple(str(t) for t in opt.children)
            elif key == "mode":
                mode = str(opt.children[0])
                if mode not in CHECK_MODES:
                    raise self.err(opt, f"mode must be one of {', '.join(CHECK_MODES)}")
                params[key] = mode
            else:
                params[key] = str(opt.children[0])
        return Check(id=str(name), type=type_, params=params)

    def ruleset(self, node: Tree) -> Ruleset:
        name = self.tokens(node, "NAME")[0]
        includes: list[str] = []
        disabled: set[str] = set()
        enabled: set[str] = set()
        for it in [c for c in node.children if isinstance(c, Tree)]:
            if it.data == "rs_include":
                includes.append(unescape(it.children[0]))
            elif it.data == "rs_disable":
                disabled.add(str(it.children[0]))
            elif it.data == "rs_enable":
                enabled.add(str(it.children[0]))
        return Ruleset(str(name), tuple(includes), frozenset(disabled), frozenset(enabled))


_CMP = {"eq": "=", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">="}
_AGG_FN = {"sum", "max", "min", "count", "count_distinct"}


class _Scope:
    """Expression builder bound to a set of event variables."""

    def __init__(self, b: _Builder, vars_: tuple[str, ...], implicit: bool) -> None:
        self.b = b
        self.vars = vars_
        self.implicit = implicit  # single implicit variable: unqualified fields resolve to None

    def qfield(self, node: Tree) -> QField:
        tok = node.children[0]
        if node.data == "qf_name":
            path = str(tok)
            var = None
        elif node.data == "qf_dotted":
            head, _, rest = str(tok).partition(".")
            if head in self.vars:
                var, path = head, rest
            else:
                var, path = None, str(tok)
        elif node.data == "qf_udm":
            var, path = None, ef.udm_field(unescape(tok))
        else:  # qf_var_udm: "<var>.udm" "(" STRING ")"
            head, _, fn = str(tok).rpartition(".")
            if fn != "udm" or "." in head:
                raise self.b.err(
                    tok, f'{tok!s}(...) is not a field; only <var>.udm("...") is allowed'
                )
            if head not in self.vars:
                raise self.b.err(tok, f"unknown event variable {head!r}")
            var, path = head, ef.udm_field(unescape(node.children[1]))
        if var is None and not self.implicit and len(self.vars) > 1 and not ef.is_known_field(path):
            raise self.b.err(tok, f"unknown event variable or field {path!r}")
        if not ef.is_known_field(path):
            raise self.b.err(
                tok, f"unknown field {path!r}; event-model fields: {ef.describe_fields()}"
            )
        return (var, path)

    def join(self, node: Tree) -> Join:
        left = self.qfield(node.children[0])
        right = self.qfield(node.children[1])
        if left[0] is None or right[0] is None:
            raise self.b.err(node, "join sides must be qualified with an event variable")
        if left[0] == right[0]:
            raise self.b.err(node, f"join joins {left[0]} with itself")
        return Join(left, right)

    # --- predicates -------------------------------------------------------------------
    def expr(self, node: Tree) -> Pred:
        d = node.data
        if d == "or_":
            return any_of([self.expr(c) for c in node.children])
        if d == "and_":
            return all_of([self.expr(c) for c in node.children])
        if d == "not_":
            return Not(child=self.expr(node.children[0]))
        if d == "const":
            return Const(value=node.children[0].data == "true")
        if d == "unknown":
            return Unknown(label=unescape(node.children[0]))
        if d == "exists":
            return Exists(field=self.qfield(node.children[0]))
        if d == "missing":
            return Not(child=Exists(field=self.qfield(node.children[0])))
        quant = None
        children = list(node.children)
        if children and isinstance(children[0], Tree) and children[0].data in {"all", "any"}:
            quant = children.pop(0).data
        nocase = bool(children and isinstance(children[-1], Tree) and children[-1].data == "nocase")
        if nocase:
            children.pop()
        field = self.qfield(children[0])
        rest = children[1:]
        common = {"field": field, "nocase": nocase, "quant": quant}
        if d == "cmp":
            op = _CMP[rest[0].data]
            value = self.b.value(rest[1])
            return Cmp(op=op, value=value, **common)  # type: ignore[arg-type]
        if d == "like":
            return Like(pattern=unescape(rest[0]), **common)  # type: ignore[arg-type]
        if d == "regex":
            rx_tok = rest[0].children[0]
            pattern = unescape_regex(rx_tok) if rx_tok.type == "REGEX" else unescape(rx_tok)
            return Regex(pattern=pattern, **common)  # type: ignore[arg-type]
        if d == "strfn":
            return StrFn(fn=rest[0].data, value=unescape(rest[1]), **common)  # type: ignore[arg-type]
        if d == "in_values":
            return In(values=tuple(self.b.value(v) for v in rest), **common)  # type: ignore[arg-type]
        if d == "in_cidr":
            return InCidr(cidrs=tuple(unescape(t) for t in rest), **common)  # type: ignore[arg-type]
        if d in {"in_ref", "in_ref_regex", "in_ref_cidr"}:
            kind = {"in_ref": "string", "in_ref_regex": "regex", "in_ref_cidr": "cidr"}[d]
            return InList(list_name=str(rest[0].children[0]), kind=kind, **common)  # type: ignore[arg-type]
        raise self.b.err(node, f"unsupported expression {d}")

    # --- aggregates -------------------------------------------------------------------
    def agg(self, node: Tree | Token) -> AggExpr:
        if isinstance(node, Token):
            return AggConst(int(node)) if node.type == "NUMBER" else AggRef(str(node))
        d = node.data
        if d == "agg_const":
            return AggConst(int(node.children[0]))
        if d == "agg_ref":
            return AggRef(str(node.children[0]))
        if d in {"agg_add", "agg_sub"}:
            return AggBin(
                "+" if d == "agg_add" else "-",
                self.agg(node.children[0]),
                self.agg(node.children[1]),
            )
        if d in {"agg_mul", "agg_div"}:
            return AggBin(
                "*" if d == "agg_mul" else "/",
                self.agg(node.children[0]),
                AggConst(int(node.children[1])),
            )
        if d == "agg_if":
            return AggIf(
                self.expr(node.children[0]), self.agg(node.children[1]), self.agg(node.children[2])
            )
        if d == "agg_call":
            fn = node.children[0].data
            arg = self.qfield(node.children[1]) if len(node.children) > 1 else None
            if arg is not None and arg[0] is None and len(self.vars) > 1:
                raise self.b.err(
                    node, f"aggregate over unqualified field {arg[1]!r}; name the event variable"
                )
            if fn != "count" and arg is None:
                raise self.b.err(node, f"{fn}() needs a field argument")
            return AggCall(fn, arg)  # type: ignore[arg-type]
        raise self.b.err(node, f"unsupported aggregate {d}")
