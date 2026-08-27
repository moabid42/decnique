"""Encode a single-event :class:`~decnique.model.predicates.Pred` as a Z3 formula (plan §M2).

Design contract (why this is sound despite an incomplete encoding):

* The encoding is **2-valued** — it is a *generator* of candidate events, not the arbiter.
  Anything the encoder cannot translate exactly (``Unknown`` atoms, string ordering, IPv6,
  ``all``-quantified repeated fields, reference lists) becomes a **fresh Boolean** that the
  solver may set freely, and is **recorded** in :class:`Encoder.approx`.
* Truth is decided by the concrete oracle: every solver model is decoded and replayed through
  :func:`decnique.dsl.interpret.observes`.  A free Boolean can only make the *generator*
  propose an event; if the concrete replay disagrees, the caller refines.  So imprecision costs
  completeness/among refinements, never soundness (Invariant #3).
* A model that *relied* on any recorded approximate atom is reported ``approximate``.

Missing-field semantics mirror :func:`decnique.dsl.interpret.evaluate` (non-partial): a leaf on
an absent field is False.  Hence every value leaf is conjoined with the field's presence term,
and ``Exists`` is exactly the presence term.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import z3

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
    Regex,
    StrFn,
    Unknown,
)
from decnique.smt.encode_event import SymEvent, any_char, any_char_star


@dataclass
class ApproxAtom:
    """A sub-formula the encoder could not translate exactly."""

    label: str
    var: z3.BoolRef


@dataclass
class Encoder:
    """Encodes predicates over one :class:`SymEvent`, accumulating approximate atoms."""

    ev: SymEvent
    approx: list[ApproxAtom] = field(default_factory=list)
    _n: int = 0

    def _fresh(self, label: str) -> z3.BoolRef:
        self._n += 1
        b = z3.Bool(f"~approx.{self._n}.{label}")
        self.approx.append(ApproxAtom(label, b))
        return b

    # -- entry -----------------------------------------------------------------------------

    def pred(self, p: Pred) -> z3.BoolRef:
        if isinstance(p, Const):
            return z3.BoolVal(p.value)
        if isinstance(p, Unknown):
            return self._fresh(p.label)
        if isinstance(p, Not):
            return z3.Not(self.pred(p.child))
        if isinstance(p, All):
            return z3.And(*[self.pred(c) for c in p.children]) if p.children else z3.BoolVal(True)
        if isinstance(p, Any):
            return z3.Or(*[self.pred(c) for c in p.children]) if p.children else z3.BoolVal(False)
        if isinstance(p, Exists):
            return self.ev.present(p.field[1])
        return self._leaf(p)

    # -- leaves ----------------------------------------------------------------------------

    def _leaf(self, p: Pred) -> z3.BoolRef:
        path = p.field[1]
        present = self.ev.present(path)
        # repeated field with `all` quantifier: the value semantics need every element →
        # a single-element model cannot decide it soundly.
        if ef.is_repeated(path) and getattr(p, "quant", None) == "all":
            return z3.And(present, self._fresh("repeated_all"))
        body = self._leaf_body(p, path)
        return z3.And(present, body)

    def _leaf_body(self, p: Pred, path: str) -> z3.BoolRef:
        sort = self.ev.sort_of(path)
        term = self.ev.term(path)
        if isinstance(p, Cmp):
            return self._cmp(p, term, sort)
        if isinstance(p, In):
            return self._in(p, term, sort)
        if isinstance(p, InCidr):
            return self._in_cidr(p, term, sort)
        if isinstance(p, Like):
            if sort not in ("string", "strings"):
                return self._fresh("like_nonstring")
            return z3.InRe(term, _glob_to_re(p.pattern, p.nocase))
        if isinstance(p, StrFn):
            return self._strfn(p, term, sort)
        if isinstance(p, Regex):
            return self._fresh("regex")  # RE2→Z3 not attempted; honest approximation
        if isinstance(p, InList):
            return self._fresh(f"reflist:{p.list_name}")
        return self._fresh("leaf")

    def _cmp(self, p: Cmp, term: z3.ExprRef, sort: str) -> z3.BoolRef:
        if sort == "bool":
            want = _as_bool(p.value)
            if want is None:
                return self._fresh("cmp_bool")
            eq = term == z3.BoolVal(want)
            return eq if p.op == "=" else z3.Not(eq) if p.op == "!=" else z3.BoolVal(False)
        if sort in ("int", "time"):
            try:
                n = int(p.value)
            except (TypeError, ValueError):
                return self._fresh("cmp_int_badval")
            return _ordered_z3(p.op, term, z3.IntVal(n))
        if sort == "ip":
            return self._ip_eq(p, term)
        # string / strings
        if p.op in ("=", "!="):
            eq = term == z3.StringVal(_s(p.value, p.nocase))
            body = eq if p.op == "=" else z3.Not(eq)
            return self._nocase(p, body, "cmp_nocase")
        return self._fresh("string_order")  # no Z3 lexicographic order

    def _in(self, p: In, term: z3.ExprRef, sort: str) -> z3.BoolRef:
        if sort in ("int", "time"):
            opts = []
            for v in p.values:
                try:
                    opts.append(term == z3.IntVal(int(v)))
                except (TypeError, ValueError):
                    return self._fresh("in_int_badval")
            return z3.Or(*opts) if opts else z3.BoolVal(False)
        if sort == "ip":
            return z3.Or(*[self._ip_eq_val(term, v) for v in p.values]) if p.values else z3.BoolVal(False)
        if sort == "bool":
            return self._fresh("in_bool")
        opts = [term == z3.StringVal(_s(v, p.nocase)) for v in p.values]
        body = z3.Or(*opts) if opts else z3.BoolVal(False)
        return self._nocase(p, body, "in_nocase")

    def _in_cidr(self, p: InCidr, term: z3.ExprRef, sort: str) -> z3.BoolRef:
        if sort != "ip":
            return self._fresh("cidr_nonip")
        clauses = []
        for c in p.cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError:
                continue
            if net.version != 4:
                return z3.Or(self._fresh("cidr_ipv6"))  # IPv6 not modeled → approximate
            base = int(net.network_address)
            mask = (0xFFFFFFFF << (32 - net.prefixlen)) & 0xFFFFFFFF
            clauses.append((term & z3.BitVecVal(mask, 32)) == z3.BitVecVal(base & mask, 32))
        return z3.Or(*clauses) if clauses else z3.BoolVal(False)

    def _strfn(self, p: StrFn, term: z3.ExprRef, sort: str) -> z3.BoolRef:
        if sort not in ("string", "strings"):
            return self._fresh("strfn_nonstring")
        if p.nocase:
            return self._fresh("strfn_nocase")  # case-fold on unbounded strings → approximate
        sub = z3.StringVal(p.value)
        if p.fn == "startswith":
            return z3.PrefixOf(sub, term)
        if p.fn == "endswith":
            return z3.SuffixOf(sub, term)
        return z3.Contains(term, sub)

    # -- ip helpers ------------------------------------------------------------------------

    def _ip_eq(self, p: Cmp, term: z3.ExprRef) -> z3.BoolRef:
        if p.op not in ("=", "!="):
            return self._fresh("ip_order")
        body = self._ip_eq_val(term, p.value)
        return body if p.op == "=" else z3.Not(body)

    def _ip_eq_val(self, term: z3.ExprRef, value: object) -> z3.BoolRef:
        try:
            addr = ipaddress.ip_address(str(value))
        except ValueError:
            return z3.BoolVal(False)
        if addr.version != 4:
            return self._fresh("ip_v6_literal")
        return term == z3.BitVecVal(int(addr), 32)

    # -- misc ------------------------------------------------------------------------------

    def _nocase(self, p: Pred, body: z3.BoolRef, label: str) -> z3.BoolRef:
        # A case-insensitive equality on an unbounded string cannot be captured by a single
        # literal; keep the exact-case branch but also allow the approximate branch.
        return z3.Or(body, self._fresh(label)) if getattr(p, "nocase", False) else body


def _glob_to_re(pattern: str, nocase: bool) -> z3.ReRef:
    """fnmatch-style glob → a full-match Z3 regex.  ``nocase`` folds ASCII letters."""
    parts: list[z3.ReRef] = []
    for ch in pattern:
        if ch == "*":
            parts.append(any_char_star())
        elif ch == "?":
            parts.append(any_char())
        elif nocase and ch.isalpha():
            parts.append(z3.Union(z3.Re(z3.StringVal(ch.lower())), z3.Re(z3.StringVal(ch.upper()))))
        else:
            parts.append(z3.Re(z3.StringVal(ch)))
    if not parts:
        return z3.Re(z3.StringVal(""))
    out = parts[0]
    for pr in parts[1:]:
        out = z3.Concat(out, pr)
    return out


def _ordered_z3(op: str, a: z3.ExprRef, b: z3.ExprRef) -> z3.BoolRef:
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


def _s(v: object, nocase: bool) -> str:
    s = str(v)
    return s.lower() if nocase else s
