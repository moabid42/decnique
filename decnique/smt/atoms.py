"""Atom abstraction of string fields (docs/COVERAGE_ABSTRACTION.md §2).

A string field's exact value never matters to coverage — only *which atomic tests* the rules
make on it hold.  An :class:`Atom` is one such test ``(field, kind, literal, nocase)``; every
string leaf of every rule becomes a Boolean variable for its atom, so the coverage query is a
propositional formula (plus the cheap exact theories for ``ip`` / ``int`` / ``bool``, which
the parent :class:`~decnique.smt.encode_pred.Encoder` still handles).  No z3 string theory.

Two pieces live here:

* :class:`AtomEncoder` — ``Pred → z3.BoolRef`` over atoms.  Method-independent, so a rule is
  encoded once per library and reused for every permission.
* :class:`Realizer` — turns a model's atom assignment on one field back into a concrete
  string, checked leaf-by-leaf with the concrete interpreter.  When no string can be built it
  returns *proven* implication clauses explaining the conflict (an ``=`` literal decides every
  other atom on its field; a substring literal implies its own substrings; two ``startswith``
  literals that are not prefixes of each other exclude one another).  These are learned
  permanently, CEGAR-style, so an UNSAT after only proven clauses is still a proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import z3

from decnique.dsl.interpret import _leaf as _concrete_leaf
from decnique.model import event_fields as ef
from decnique.model.predicates import Cmp, In, Like, Pred, Regex, StrFn, Value
from decnique.smt.encode_event import SymEvent
from decnique.smt.encode_pred import Encoder

SUBSTRING_KINDS = ("contains", "startswith", "endswith")


@dataclass(frozen=True, slots=True)
class Atom:
    """One atomic test on a string field."""

    field: str
    kind: str  # eq | contains | startswith | endswith | glob | regex
    literal: Value
    nocase: bool = False

    @property
    def text(self) -> str:
        return str(self.literal)

    @property
    def folded(self) -> str:
        """The literal as the *value* would be compared: case-folded iff ``nocase``."""
        return self.text.lower() if self.nocase else self.text

    def pred(self) -> Pred:
        qf = (None, self.field)
        if self.kind == "eq":
            return Cmp(field=qf, op="=", value=self.literal, nocase=self.nocase)
        if self.kind in SUBSTRING_KINDS:
            return StrFn(field=qf, fn=self.kind, value=self.text, nocase=self.nocase)  # type: ignore[arg-type]
        if self.kind == "glob":
            return Like(field=qf, pattern=self.text, nocase=self.nocase)
        return Regex(field=qf, pattern=self.text, nocase=self.nocase)

    def holds(self, value: str) -> bool | None:
        """Concrete three-valued truth of this atom on ``value`` (the interpreter decides)."""
        return _concrete_leaf(self.pred(), value, None)


@dataclass
class AtomTable:
    """Interns atoms to z3 Booleans; groups them by field."""

    vars: dict[Atom, z3.BoolRef] = field(default_factory=dict)
    by_field: dict[str, list[Atom]] = field(default_factory=dict)

    def var(self, atom: Atom) -> z3.BoolRef:
        v = self.vars.get(atom)
        if v is None:
            n = len(self.vars)
            v = z3.Bool(f"atom.{n}.{atom.field}.{atom.kind}")
            self.vars[atom] = v
            self.by_field.setdefault(atom.field, []).append(atom)
        return v

    def eq(self, path: str, literal: Value, nocase: bool = False) -> z3.BoolRef:
        return self.var(Atom(path, "eq", literal, nocase))

    def eq_exclusion(self, path: str) -> list[z3.BoolRef]:
        """Eager, cheap consistency for the ``=`` atoms of one field: at most one case-folded
        literal group is true; inside a group distinct case-sensitive literals exclude each
        other and each case-sensitive one implies the case-insensitive one."""
        groups: dict[str, list[Atom]] = {}
        for a in self.by_field.get(path, ()):
            if a.kind == "eq":
                groups.setdefault(a.text.lower(), []).append(a)
        out: list[z3.BoolRef] = []
        if len(groups) > 1:
            out.append(z3.AtMost(*[z3.Or(*[self.var(a) for a in g]) for g in groups.values()], 1))
        for g in groups.values():
            cs = [a for a in g if not a.nocase]
            nc = [a for a in g if a.nocase]
            for i, a in enumerate(cs):
                for b in cs[i + 1 :]:
                    if a.text != b.text:
                        out.append(z3.Not(z3.And(self.var(a), self.var(b))))
                for c in nc:
                    out.append(z3.Implies(self.var(a), self.var(c)))
        return out


class AtomEncoder(Encoder):
    """The parent encoder with every string-sorted leaf routed to an atom variable."""

    def __init__(self, table: AtomTable, prefix: str = "e") -> None:
        super().__init__(ev=SymEvent(prefix=prefix))
        self.table = table

    def _leaf_body(self, p: Pred, path: str) -> z3.BoolRef:  # type: ignore[override]
        if self.ev.sort_of(path) not in ("string", "strings"):
            return super()._leaf_body(p, path)
        if isinstance(p, Cmp):
            if p.op not in ("=", "!="):
                return self._fresh("string_order")
            a = self.table.eq(path, p.value, p.nocase)
            return a if p.op == "=" else z3.Not(a)
        if isinstance(p, In):
            opts = [self.table.eq(path, v, p.nocase) for v in p.values]
            return z3.Or(*opts) if opts else z3.BoolVal(False)
        if isinstance(p, StrFn):
            return self.table.var(Atom(path, p.fn, p.value, p.nocase))
        if isinstance(p, Like):
            kind, lit = simple_glob(p.pattern)
            return self.table.var(Atom(path, kind, lit, p.nocase))
        if isinstance(p, Regex):
            try:
                re.compile(p.pattern)
            except re.error:
                return self._fresh("regex_invalid")
            return self.table.var(Atom(path, "regex", p.pattern, p.nocase))
        return super()._leaf_body(p, path)  # InCidr / InList on a string → approximate


# --- realization -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Realized:
    value: str | None  # None: no string found
    learned: tuple[z3.BoolRef, ...] = ()  # proven clauses violated by the offending model

    @property
    def ok(self) -> bool:
        return self.value is not None


class Realizer:
    """Build a concrete string for one field from its true / false atoms."""

    def __init__(self, table: AtomTable) -> None:
        self.table = table
        self._memo: dict[tuple[Atom, str], bool | None] = {}

    def holds(self, a: Atom, value: str) -> bool | None:
        key = (a, value)
        if key not in self._memo:
            self._memo[key] = a.holds(value)
        return self._memo[key]

    def realize(
        self, true: list[Atom], false: list[Atom], examples: tuple[str, ...] = ()
    ) -> Realized:
        """``examples`` are realistic values to prefer when no atom forces a value."""
        for cand in self._candidates(true, examples):
            if all(self.holds(a, cand) is True for a in true) and all(
                self.holds(a, cand) is False for a in false
            ):
                return Realized(cand)
        return Realized(None, tuple(self._explain(true, false)))

    # -- candidates ----------------------------------------------------------------------

    def _candidates(self, true: list[Atom], examples: tuple[str, ...] = ()) -> list[str]:
        eqs = [a for a in true if a.kind == "eq"]
        if eqs:
            lit = next((a.text for a in eqs if not a.nocase), eqs[0].text)
            return _dedupe([lit, lit.lower(), lit.upper(), lit.capitalize()])
        pre = [a.text for a in true if a.kind == "startswith"]
        suf = [a.text for a in true if a.kind == "endswith"]
        mid = [a.text for a in true if a.kind == "contains"]
        mid += [_glob_seed(a.text) for a in true if a.kind == "glob"]
        pre.sort(key=len, reverse=True)
        suf.sort(key=len, reverse=True)
        head = pre[0] if pre else ""
        tail = suf[0] if suf else ""
        mids = [m for m in mid if m.lower() not in head.lower() and m.lower() not in tail.lower()]
        if not (head or tail or mids):
            return _dedupe([*examples, "", "-", "x"])
        out: list[str] = []
        for order in (mids, list(reversed(mids))):
            for sep in ("", "-", "_", " ", "/"):
                out.append(head + sep.join(order) + tail)
                out.append(head + sep + sep.join(order) + sep + tail)
        return _dedupe(out)

    # -- proven explanations -------------------------------------------------------------

    def _explain(self, true: list[Atom], false: list[Atom]) -> list[z3.BoolRef]:
        v = self.table.var
        out: list[z3.BoolRef] = []
        # 1. an `=` literal decides every other atom on the field
        for e in (a for a in true if a.kind == "eq"):
            for a in true + false:
                if a is e:
                    continue
                if e.nocase and not a.nocase and a.kind != "eq":
                    continue  # a case-insensitive `=` does not decide case-sensitive tests
                if a.kind == "eq" and e.nocase and not a.nocase:
                    if a.text.lower() != e.text.lower():
                        out.append(z3.Not(z3.And(v(e), v(a))))  # different folded literals
                    continue
                h = a.holds(e.text)
                if h is None:
                    continue
                if h and a in false:
                    out.append(z3.Implies(v(e), v(a)))
                elif not h and a in true:
                    out.append(z3.Implies(v(e), z3.Not(v(a))))
        # 2. a substring literal implies its own substrings / prefixes / suffixes
        for t in (a for a in true if a.kind in SUBSTRING_KINDS):
            for f in (a for a in false if a.kind in SUBSTRING_KINDS):
                if _implies(t, f):
                    out.append(z3.Implies(v(t), v(f)))
        # 3. two prefixes (suffixes) that are not nested exclude each other
        for kind, fn in (("startswith", str.startswith), ("endswith", str.endswith)):
            ks = [a for a in true if a.kind == kind]
            for i, a in enumerate(ks):
                for b in ks[i + 1 :]:
                    x, y = a.text.lower(), b.text.lower()
                    if not (fn(x, y) or fn(y, x)):
                        out.append(z3.Not(z3.And(v(a), v(b))))
        return out


def _implies(t: Atom, f: Atom) -> bool:
    """Does every string satisfying ``t`` satisfy ``f``?  (substring kinds only, proven)"""
    if t.nocase and not f.nocase:
        return False
    lt, lf = (t.text.lower(), f.text.lower()) if f.nocase else (t.text, f.text)
    if f.kind == "contains":
        return lf in lt
    if f.kind == "startswith":
        return t.kind == "startswith" and lt.startswith(lf)
    return t.kind == "endswith" and lt.endswith(lf)


def simple_glob(pattern: str) -> tuple[str, str]:
    """Classify a glob as an exact substring test when it has that shape — ``*lit*`` is
    ``contains``, ``lit*`` ``startswith``, ``*lit`` ``endswith``, a bare literal ``eq`` — so the
    consistency reasoning of the substring kinds applies.  Anything else stays ``glob``."""
    core = pattern.strip("*")
    if not core or any(c in core for c in "*?["):
        return "glob", pattern
    lead, trail = pattern.startswith("*"), pattern.endswith("*")
    if lead and trail:
        return "contains", core
    if trail:
        return "startswith", core
    if lead:
        return "endswith", core
    return "eq", core


def _glob_seed(pattern: str) -> str:
    return pattern.replace("*", "").replace("?", "a")


def _dedupe(xs: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for x in xs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def is_string_sort(path: str) -> bool:
    return ef.field_sort(path) in ("string", "strings")
