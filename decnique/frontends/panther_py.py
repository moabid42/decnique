"""Panther ``rule(event)`` bodies → predicates, by symbolic evaluation of the Python AST.

A Panther rule is a Python function over one ``GCP.AuditLog`` record.  The corpus uses a small,
regular subset — ``event.deep_get(...)`` / ``event.get(...)`` / ``event.deep_walk(...)`` reads,
comparisons with literals, ``in`` over literal tuples and module constants, ``startswith`` /
``endswith`` / ``lower``, ``and`` / ``or`` / ``not``, early ``return`` guards, ``for`` over
``authorizationInfo`` or the binding deltas, ``any`` / ``all`` over literal lists, and small
helper functions defined in the same file.  This module evaluates exactly that subset into the
event model; every construct outside it becomes an ``Unknown`` atom naming the construct and
the fields it reads, so the rule stays *approximate* rather than silently broadened or
narrowed (honesty invariant #1).

Semantics of a body: the predicate under which ``rule()`` returns a truthy value.  A block is
evaluated to ``(returned, falls_through)`` — two predicates; ``if`` splits on the test, an
early ``return False`` contributes nothing to ``returned`` and blocks the fall-through path.

Field mapping (raw Cloud Audit Log entry → event model)::

    protoPayload.methodName                          method
    protoPayload.serviceName                         service
    protoPayload.authenticationInfo.principalEmail   principal
    protoPayload.resourceName                        resource
    protoPayload.requestMetadata.callerIp            caller_ip
    protoPayload.requestMetadata.callerSuppliedUserAgent   user_agent
    logName                                          log_name
    resource.labels.project_id                       project
    protoPayload.authorizationInfo[].permission      permission   (any element)
    protoPayload.authorizationInfo[].granted         granted
    …serviceData.policyDelta.bindingDeltas[].{action,role,member}   the UDM delta labels
    anything else                                    udm:<dotted raw path>
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from decnique.model import event_fields as ef
from decnique.model.predicates import (
    All,
    Any,
    Cmp,
    Const,
    Exists,
    In,
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

_DELTA_LABEL = "udm:target.resource.attribute.labels[ser_binding_deltas_{}]"
_PATHS: dict[tuple[str, ...], str] = {
    ("protoPayload", "methodName"): "method",
    ("protoPayload", "serviceName"): "service",
    ("protoPayload", "authenticationInfo", "principalEmail"): "principal",
    ("protoPayload", "resourceName"): "resource",
    ("protoPayload", "requestMetadata", "callerIp"): "caller_ip",
    ("protoPayload", "requestMetadata", "callerSuppliedUserAgent"): "user_agent",
    ("logName",): "log_name",
    ("resource", "labels", "project_id"): "project",
}
_AUTH_INFO = ("protoPayload", "authorizationInfo")
_DELTAS = ("protoPayload", "serviceData", "policyDelta", "bindingDeltas")
_AUTH_KEYS = {"permission": "permission", "granted": "granted", "resource": "resource"}
_DELTA_KEYS = {k: _DELTA_LABEL.format(k) for k in ("action", "role", "member")}


class Unsupported(Exception):
    """A construct outside the evaluated subset (carries the fields it touched)."""

    def __init__(self, what: str, fields: tuple[str, ...] = ()) -> None:
        super().__init__(what)
        self.what = what
        self.fields = fields


# --- values -------------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldV:
    """A read of one event field, possibly lower-cased."""

    path: str
    nocase: bool = False


@dataclass(frozen=True)
class ListV:
    """An iterable of records: the authorizationInfo entries or the binding deltas."""

    kind: str  # auth | delta
    keys: dict[str, str] = field(default_factory=dict, hash=False, compare=False)


@dataclass(frozen=True)
class RecordV:
    """One element of a ListV (the loop variable)."""

    keys: dict[str, str] = field(default_factory=dict, hash=False, compare=False)


@dataclass(frozen=True)
class RegexV:
    """A compiled pattern (``re.compile(...)`` at module level)."""

    pattern: str


@dataclass(frozen=True)
class UdmTypeV:
    """``event.udm("event_type")`` — Panther's data model; for GCP.AuditLog it yields
    ADMIN_ROLE_ASSIGNED on an admin-role grant and nothing else (see :mod:`panther`)."""


@dataclass(frozen=True)
class RawV:
    """A read the model has no field for, kept by its raw dotted path (``udm:``)."""

    keys: tuple[str, ...]


Value = FieldV | ListV | RecordV | RawV | RegexV | UdmTypeV | Pred | str | int | bool | float | None | tuple | list | set


def _qf(path: str) -> QField:
    return (None, path)


def _field_of(keys: tuple[str, ...]) -> Value:
    if keys in _PATHS:
        return FieldV(_PATHS[keys])
    if keys == _AUTH_INFO:
        return ListV("auth", dict(_AUTH_KEYS))
    if keys == _DELTAS:
        return ListV("delta", dict(_DELTA_KEYS))
    if len(keys) == len(_AUTH_INFO) + 1 and keys[:-1] == _AUTH_INFO:
        return FieldV(_AUTH_KEYS.get(keys[-1], "udm:" + ".".join(keys)))
    if len(keys) == len(_DELTAS) + 1 and keys[:-1] == _DELTAS:
        return FieldV(_DELTA_KEYS.get(keys[-1], "udm:" + ".".join(keys)))
    return FieldV("udm:" + ".".join(keys))


def _fields_in(v: Value) -> tuple[str, ...]:
    if isinstance(v, FieldV):
        return (v.path,)
    if isinstance(v, RawV):
        return ("udm:" + ".".join(v.keys),)
    return ()


# --- the evaluator ------------------------------------------------------------------------


class _Eval:
    def __init__(self, module: ast.Module) -> None:
        self.consts: dict[str, Value] = {}
        self.funcs: dict[str, ast.FunctionDef] = {}
        self.imported: set[str] = set()
        self.unsupported: list[str] = []
        for node in module.body:
            if isinstance(node, ast.FunctionDef):
                self.funcs[node.name] = node
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                try:
                    self.consts[node.targets[0].id] = self.expr(node.value, {})
                except Unsupported:
                    pass
            elif isinstance(node, ast.ImportFrom | ast.Import):
                for a in node.names:
                    self.imported.add(a.asname or a.name)

    # -- entry ---------------------------------------------------------------------------

    def rule(self) -> Pred:
        fn = self.funcs.get("rule")
        if fn is None:
            raise Unsupported("no rule() function")
        env: dict[str, Value] = {fn.args.args[0].arg: "event"} if fn.args.args else {}
        returned, _ = self.block(fn.body, env, depth=0)
        return returned

    # -- statements: (returned-truthy, falls-through) ------------------------------------

    def block(self, stmts: list[ast.stmt], env: dict[str, Value], depth: int) -> tuple[Pred, Pred]:
        returned: list[Pred] = []
        path: Pred = Const(value=True)  # condition under which we reach the current statement
        for st in stmts:
            if isinstance(path, Const) and not path.value:
                break
            try:
                r, f = self.stmt(st, env, depth)
            except Unsupported as u:
                # the rest of the body is a black box: it may return anything
                self.unsupported.append(u.what)
                returned.append(all_of([path, Unknown(label=f"panther:python:{u.what}", raw=_src(st),
                                                      fields=tuple(_qf(x) for x in u.fields))]))
                return any_of(returned), Const(value=False)
            returned.append(all_of([path, r]))
            path = all_of([path, f])
        return any_of(returned) if returned else Const(value=False), path

    def stmt(self, st: ast.stmt, env: dict[str, Value], depth: int) -> tuple[Pred, Pred]:
        if isinstance(st, ast.Return):
            return (self.truth(st.value, env) if st.value is not None else Const(value=False)), Const(value=False)
        if isinstance(st, ast.If):
            t = self.truth(st.test, env)
            br, bf = self.block(st.body, dict(env), depth)
            er, ef = self.block(st.orelse, dict(env), depth)
            return any_of([all_of([t, br]), all_of([Not(child=t), er])]), any_of([all_of([t, bf]), all_of([Not(child=t), ef])])
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            env[st.targets[0].id] = self.expr(st.value, env)
            return Const(value=False), Const(value=True)
        if isinstance(st, ast.For) and isinstance(st.target, ast.Name):
            return self.for_stmt(st, env, depth)
        if isinstance(st, ast.Expr | ast.Pass | ast.Global | ast.Nonlocal):
            return Const(value=False), Const(value=True)
        if isinstance(st, ast.Continue):
            return Const(value=False), Const(value=False)
        raise Unsupported(type(st).__name__.lower())

    def for_stmt(self, st: ast.For, env: dict[str, Value], depth: int) -> tuple[Pred, Pred]:
        it = self.expr(st.iter, env)
        if not isinstance(it, ListV):
            raise Unsupported("for_over_" + type(it).__name__.lower(), _fields_in(it))
        inner = dict(env)
        inner[st.target.id] = RecordV(it.keys)
        r, _ = self.block(st.body, inner, depth)
        # "some element makes the body return truthy"; the model keeps one representative
        # element per event (the first authorizationInfo / the binding delta it carries)
        return r, Const(value=True)

    # -- expressions ---------------------------------------------------------------------

    def expr(self, e: ast.expr, env: dict[str, Value]) -> Value:
        if isinstance(e, ast.Constant):
            return e.value
        if isinstance(e, ast.Name):
            if e.id in env:
                return env[e.id]
            if e.id in self.consts:
                return self.consts[e.id]
            if e.id in self.imported or e.id in ("re", "fnmatch", "event_type"):
                return e.id
            raise Unsupported(f"name:{e.id}")
        if isinstance(e, ast.Tuple | ast.List | ast.Set):
            return tuple(self.expr(x, env) for x in e.elts)
        if isinstance(e, ast.Call):
            return self.call(e, env)
        if isinstance(e, ast.Attribute):
            base = self.expr(e.value, env)
            if base == "event_type":
                return ("event_type", e.attr)
            raise Unsupported(f"attribute:{e.attr}", _fields_in(base))
        if isinstance(e, ast.Subscript):
            base = self.expr(e.value, env)
            if isinstance(base, RecordV) and isinstance(e.slice, ast.Constant) and isinstance(e.slice.value, str):
                return FieldV(base.keys.get(e.slice.value, "udm:" + e.slice.value))
            raise Unsupported("subscript", _fields_in(base))
        if isinstance(e, ast.IfExp):
            t = self.truth(e.test, env)
            if isinstance(t, Const):  # `x if isinstance(x, list) else [x]` — decided statically
                return self.expr(e.body if t.value else e.orelse, env)
            return any_of([all_of([t, self.truth(e.body, env)]), all_of([Not(child=t), self.truth(e.orelse, env)])])
        if isinstance(e, ast.Compare | ast.BoolOp | ast.UnaryOp):
            return self.truth(e, env)
        raise Unsupported(type(e).__name__.lower())

    def call(self, e: ast.Call, env: dict[str, Value]) -> Value:
        fn = e.func
        args = e.args
        if isinstance(fn, ast.Attribute):
            recv = self.expr(fn.value, env)
            name = fn.attr
            if recv == "event":
                if name in ("deep_get", "deep_walk", "get"):
                    # get(key, default): only the first positional is a key; deep_get's
                    # default is a keyword argument, every positional is a key
                    key_args = args[:1] if name == "get" else args
                    keys = tuple(self.expr(a, env) for a in key_args)
                    if not all(isinstance(k, str) for k in keys):
                        raise Unsupported(f"event.{name}:dynamic_key")
                    return _field_of(keys)  # type: ignore[arg-type]
                if name == "udm" and args and isinstance(args[0], ast.Constant):
                    if args[0].value == "event_type":
                        return UdmTypeV()
                    raise Unsupported(f"event.udm:{args[0].value}")
                raise Unsupported(f"event.{name}")
            if isinstance(recv, RecordV) and name == "get" and args and isinstance(args[0], ast.Constant):
                k = str(args[0].value)
                return FieldV(recv.keys.get(k, "udm:" + k))
            if isinstance(recv, RecordV) and name in ("startswith", "endswith", "lower"):
                raise Unsupported(f"record.{name}")
            if isinstance(recv, FieldV):
                if name == "lower" and not args:
                    return FieldV(recv.path, nocase=True)
                if name in ("startswith", "endswith") and len(args) == 1:
                    lit = self.expr(args[0], env)
                    if isinstance(lit, str):
                        return StrFn(field=_qf(recv.path), fn=name, value=lit, nocase=recv.nocase)  # type: ignore[arg-type]
                    if isinstance(lit, tuple) and all(isinstance(x, str) for x in lit):
                        return any_of([StrFn(field=_qf(recv.path), fn=name, value=x, nocase=recv.nocase) for x in lit])  # type: ignore[arg-type]
                raise Unsupported(f"str.{name}", (recv.path,))
            if recv == "re" and name == "compile" and args:
                pat = self.expr(args[0], env)
                if isinstance(pat, str):
                    return RegexV(pat)
            if (recv == "re" and len(args) >= 2) or (isinstance(recv, RegexV) and len(args) >= 1):
                if name in ("search", "match", "fullmatch"):
                    pat = self.expr(args[0], env) if recv == "re" else recv.pattern
                    subj = self.expr(args[1] if recv == "re" else args[0], env)
                    if isinstance(pat, str) and isinstance(subj, FieldV):
                        p = pat if name == "search" else ("^" + pat if name == "match" else f"^(?:{pat})$")
                        return Regex(field=_qf(subj.path), pattern=p, nocase=subj.nocase)
            raise Unsupported(f"call:{name}", _fields_in(recv) if not isinstance(recv, str) else ())
        if isinstance(fn, ast.Name):
            name = fn.id
            if name in ("any", "all") and len(args) == 1:
                items = self.iter_truths(args[0], env)
                return any_of(items) if name == "any" else all_of(items)
            if name == "bool" and len(args) == 1:
                return self.truth(args[0], env)
            if name == "str" and len(args) == 1:
                return self.expr(args[0], env)
            if name == "isinstance" and len(args) == 2 and isinstance(args[1], ast.Name):
                v = self.expr(args[0], env)
                if args[1].id == "list":  # the list-valued reads of the audit record
                    return isinstance(v, ListV) or (isinstance(v, FieldV) and v.path in _AUTH_KEYS.values())
                if args[1].id in ("str", "dict"):
                    return isinstance(v, FieldV) if args[1].id == "str" else isinstance(v, RecordV)
            if name == "int" and len(args) == 1:
                v = self.expr(args[0], env)
                if isinstance(v, FieldV):
                    return v  # numeric comparison happens in the compare
                raise Unsupported("int()")
            if name == "fnmatch" and len(args) == 2:
                subj, pat = self.expr(args[0], env), self.expr(args[1], env)
                if isinstance(subj, FieldV) and isinstance(pat, str):
                    return Like(field=_qf(subj.path), pattern=pat, nocase=subj.nocase)
            if name == "get_binding_deltas" and len(args) == 1:
                return ListV("delta", dict(_DELTA_KEYS))
            if name == "deep_get" and args:  # panther_base_helpers.deep_get(event, ...)
                if self.expr(args[0], env) == "event":
                    keys = tuple(self.expr(a, env) for a in args[1:])
                    if all(isinstance(k, str) for k in keys):
                        return _field_of(keys)  # type: ignore[arg-type]
            if name in self.funcs and name != "rule":
                return self.inline(self.funcs[name], args, env)
            raise Unsupported(f"call:{name}")
        raise Unsupported("call")

    def inline(self, fn: ast.FunctionDef, args: list[ast.expr], env: dict[str, Value]) -> Value:
        """A helper defined in the same file: evaluate its body as a predicate (one level)."""
        if len(fn.args.args) != len(args):
            raise Unsupported(f"helper:{fn.name}:arity")
        inner = {a.arg: self.expr(v, env) for a, v in zip(fn.args.args, args)}
        r, _ = self.block(fn.body, inner, depth=1)
        return r

    def iter_truths(self, e: ast.expr, env: dict[str, Value]) -> list[Pred]:
        if isinstance(e, ast.List | ast.Tuple | ast.Set):
            return [self.truth(x, env) for x in e.elts]
        v = self.expr(e, env) if isinstance(e, ast.Name | ast.Call) else None
        if isinstance(v, FieldV):  # any(<list of granted flags>)
            return [self.truthy(v)]
        if isinstance(v, tuple):
            return [self.truthy(x) for x in v]
        if isinstance(e, ast.GeneratorExp | ast.ListComp) and len(e.generators) == 1:
            g = e.generators[0]
            src = self.expr(g.iter, env)
            if isinstance(g.target, ast.Name) and isinstance(src, tuple) and not g.ifs:
                out = []
                for item in src:
                    inner = dict(env)
                    inner[g.target.id] = item
                    out.append(self.truth(e.elt, inner))
                return out
            if isinstance(g.target, ast.Name) and isinstance(src, ListV) and not g.ifs:
                inner = dict(env)
                inner[g.target.id] = RecordV(src.keys)
                return [self.truth(e.elt, inner)]
        raise Unsupported("comprehension")

    # -- truth of an expression ----------------------------------------------------------

    def truth(self, e: ast.expr, env: dict[str, Value]) -> Pred:
        if isinstance(e, ast.BoolOp):
            parts = [self.truth(v, env) for v in e.values]
            return all_of(parts) if isinstance(e.op, ast.And) else any_of(parts)
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
            return Not(child=self.truth(e.operand, env))
        if isinstance(e, ast.Compare):
            return self.compare(e, env)
        v = self.expr(e, env)
        return self.truthy(v)

    def truthy(self, v: Value) -> Pred:
        if isinstance(v, Pred):
            return v
        if isinstance(v, bool | int | float | str | tuple) or v is None:
            return Const(value=bool(v))
        if isinstance(v, FieldV):  # Python truthiness by the field's sort
            sort = ef.field_sort(v.path)
            if sort == "bool":
                return Cmp(field=_qf(v.path), op="=", value=True)
            if sort == "int":
                return Not(child=Cmp(field=_qf(v.path), op="=", value=0))
            return all_of([Exists(field=_qf(v.path)), Not(child=Cmp(field=_qf(v.path), op="=", value=""))])
        if isinstance(v, ListV):
            return Const(value=True) if v.kind == "auth" else Exists(field=_qf(_DELTA_KEYS["action"]))
        raise Unsupported("truthiness", _fields_in(v))

    def compare(self, e: ast.Compare, env: dict[str, Value]) -> Pred:
        if len(e.ops) != 1:
            raise Unsupported("chained_compare")
        op = e.ops[0]
        left, right = self.expr(e.left, env), self.expr(e.comparators[0], env)
        if isinstance(op, ast.In | ast.NotIn):
            p = self.membership(left, right)
            return Not(child=p) if isinstance(op, ast.NotIn) else p
        # normalise literal-on-the-left
        if not isinstance(left, FieldV) and isinstance(right, FieldV):
            left, right = right, left
            op = {ast.Lt: ast.Gt, ast.Gt: ast.Lt, ast.LtE: ast.GtE, ast.GtE: ast.LtE}.get(type(op), type(op))()
        if isinstance(left, FieldV):
            qf = _qf(left.path)
            if isinstance(op, ast.Is | ast.IsNot | ast.Eq | ast.NotEq):
                neg = isinstance(op, ast.IsNot | ast.NotEq)
                if right is None:
                    p: Pred = Not(child=Exists(field=qf))
                elif isinstance(right, bool | int | str | float):
                    p = Cmp(field=qf, op="=", value=right if not isinstance(right, float) else int(right), nocase=left.nocase)
                else:
                    raise Unsupported("compare_with_" + type(right).__name__.lower(), (left.path,))
                return Not(child=p) if neg else p
            sym = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">="}.get(type(op))
            if sym and isinstance(right, int | float):
                return Cmp(field=qf, op=sym, value=int(right))  # type: ignore[arg-type]
            raise Unsupported("compare_op", (left.path,))
        if isinstance(left, Pred) and isinstance(right, bool) and isinstance(op, ast.Eq | ast.Is):
            return left if right else Not(child=left)
        if isinstance(left, Pred) and right is None and isinstance(op, ast.Is | ast.IsNot | ast.Eq | ast.NotEq):
            # `match = re.search(...)`, then `match is not None`
            return left if isinstance(op, ast.IsNot | ast.NotEq) else Not(child=left)
        if isinstance(left, UdmTypeV) and isinstance(op, ast.Eq | ast.NotEq):
            p = _udm_event_type(right)
            return Not(child=p) if isinstance(op, ast.NotEq) else p
        if isinstance(left, bool | int | str) and isinstance(right, bool | int | str) and isinstance(op, ast.Eq):
            return Const(value=left == right)
        raise Unsupported("compare", _fields_in(left) + _fields_in(right))

    def membership(self, left: Value, right: Value) -> Pred:
        if isinstance(left, UdmTypeV) and isinstance(right, tuple):
            return any_of([_udm_event_type(x) for x in right])
        if isinstance(left, FieldV) and isinstance(right, tuple):
            if all(isinstance(x, str | int | bool) for x in right):
                return In(field=_qf(left.path), values=tuple(right), nocase=left.nocase)
            raise Unsupported("in_non_literal", (left.path,))
        if isinstance(left, str) and isinstance(right, FieldV):
            return StrFn(field=_qf(right.path), fn="contains", value=left, nocase=right.nocase)
        raise Unsupported("in", _fields_in(left) + _fields_in(right))


def _udm_event_type(marker: Value) -> Pred:
    """What ``event.udm("event_type") == event_type.X`` means on GCP.AuditLog: Panther's
    ``gcp_data_model.py`` derives ADMIN_ROLE_ASSIGNED from a SetIamPolicy binding delta that
    ADDs ``roles/owner`` or ``roles/*Admin``, and no other event type."""
    if not (isinstance(marker, tuple) and len(marker) == 2 and marker[0] == "event_type"):
        raise Unsupported("udm_event_type")
    if marker[1] != "ADMIN_ROLE_ASSIGNED":
        return Const(value=False)
    role = _qf(_DELTA_KEYS["role"])
    return all_of([
        Cmp(field=_qf("method"), op="=", value="SetIamPolicy"),
        Cmp(field=_qf(_DELTA_KEYS["action"]), op="=", value="ADD"),
        any_of([Cmp(field=role, op="=", value="roles/owner"), Like(field=role, pattern="roles/*Admin")]),
    ])


def simplify(p: Pred) -> Pred:
    """Drop the noise symbolic evaluation leaves behind: ``not not x``, ``true and x``,
    ``false or x``, constants under ``not``.  Meaning-preserving on all three truth values."""
    if isinstance(p, Not):
        c = simplify(p.child)
        if isinstance(c, Not):
            return c.child
        if isinstance(c, Const):
            return Const(value=not c.value)
        return Not(child=c)
    if isinstance(p, All):
        kids = [simplify(c) for c in p.children]
        if any(isinstance(k, Const) and not k.value for k in kids):
            return Const(value=False)
        kids = [k for k in kids if not (isinstance(k, Const) and k.value)]
        flat: list[Pred] = []
        for k in kids:
            flat.extend(k.children if isinstance(k, All) else (k,))
        return all_of(flat) if flat else Const(value=True)
    if isinstance(p, Any):
        kids = [simplify(c) for c in p.children]
        if any(isinstance(k, Const) and k.value for k in kids):
            return Const(value=True)
        kids = [k for k in kids if not (isinstance(k, Const) and not k.value)]
        flat = []
        for k in kids:
            flat.extend(k.children if isinstance(k, Any) else (k,))
        return any_of(flat) if flat else Const(value=False)
    return p


def _src(node: ast.AST) -> str:
    try:
        return ast.unparse(node)[:120]
    except Exception:  # pragma: no cover
        return type(node).__name__


def rule_predicate(py_text: str) -> tuple[Pred, list[str]]:
    """The predicate under which ``rule(event)`` returns truthy, and the constructs that
    could not be evaluated (each also present as an ``Unknown`` atom in the predicate)."""
    try:
        module = ast.parse(py_text)
    except SyntaxError as e:
        return Unknown(label="panther:python:syntax", raw=str(e)[:120]), ["syntax"]
    ev = _Eval(module)
    try:
        pred = ev.rule()
    except Unsupported as u:
        return Unknown(label=f"panther:python:{u.what}", fields=tuple(_qf(x) for x in u.fields)), [u.what]
    return simplify(pred), ev.unsupported
