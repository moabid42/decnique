"""Atom abstraction (docs/COVERAGE_ABSTRACTION.md): globs, realization, proven learning."""

from __future__ import annotations

import z3

from decnique.smt.atoms import Atom, AtomTable, Realizer, simple_glob


def test_simple_glob_classification():
    assert simple_glob("*foo*") == ("contains", "foo")
    assert simple_glob("foo*") == ("startswith", "foo")
    assert simple_glob("*foo") == ("endswith", "foo")
    assert simple_glob("foo") == ("eq", "foo")
    assert simple_glob("*a*b*") == ("glob", "*a*b*")
    assert simple_glob("f?o*") == ("glob", "f?o*")


def test_realize_eq_and_substrings():
    r = Realizer(AtomTable())
    ok = r.realize([Atom("user_agent", "eq", "curl/8.0")], [Atom("user_agent", "contains", "python", True)])
    assert ok.value == "curl/8.0"
    ok = r.realize(
        [Atom("user_agent", "startswith", "kube"), Atom("user_agent", "contains", "probe", True)],
        [Atom("user_agent", "contains", "curl", True)],
    )
    assert ok.ok and ok.value.startswith("kube") and "probe" in ok.value and "curl" not in ok.value


def test_realize_nothing_true_gives_neutral_value():
    r = Realizer(AtomTable())
    ok = r.realize([], [Atom("resource", "contains", "x"), Atom("resource", "eq", "")])
    assert ok.ok and ok.value not in ("",) and "x" not in ok.value


def test_conflict_yields_proven_implication():
    t = AtomTable()
    r = Realizer(t)
    a, b = Atom("f", "contains", "abc"), Atom("f", "contains", "bc")
    t.var(a), t.var(b)
    res = r.realize([a], [b])  # every string containing "abc" contains "bc" → impossible
    assert not res.ok and len(res.learned) == 1
    # the learned clause is exactly a ⇒ b
    s = z3.Solver()
    s.add(res.learned[0], t.var(a), z3.Not(t.var(b)))
    assert s.check() == z3.unsat


def test_eq_decides_other_atoms():
    t = AtomTable()
    r = Realizer(t)
    e, c = Atom("f", "eq", "hello"), Atom("f", "contains", "ell", True)
    t.var(e), t.var(c)
    res = r.realize([e], [c])
    assert not res.ok and res.learned  # eq "hello" ⇒ contains "ell"


def test_nocase_eq_does_not_decide_case_sensitive_test():
    t = AtomTable()
    r = Realizer(t)
    e, c = Atom("f", "eq", "hello", True), Atom("f", "contains", "ELL")
    t.var(e), t.var(c)
    res = r.realize([e, c], [])
    assert res.ok and res.value.lower() == "hello" and "ELL" in res.value


def test_eq_exclusion_groups():
    t = AtomTable()
    a, b, c = Atom("f", "eq", "x"), Atom("f", "eq", "y"), Atom("f", "eq", "X", True)
    for at in (a, b, c):
        t.var(at)
    s = z3.Solver()
    s.add(*t.eq_exclusion("f"))
    s.push(); s.add(t.var(a), t.var(b)); assert s.check() == z3.unsat; s.pop()
    s.push(); s.add(t.var(a), z3.Not(t.var(c))); assert s.check() == z3.unsat; s.pop()  # x ⇒ X~nocase
    s.push(); s.add(t.var(c), z3.Not(t.var(a))); assert s.check() == z3.sat; s.pop()
