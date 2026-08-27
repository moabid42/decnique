"""One symbolic event as a bundle of typed Z3 variables (plan §M2).

Each event-model field becomes a Z3 term typed by its :data:`~decnique.model.event_fields.Sort`:

    string / strings -> String     (Z3 sequence-of-char; equality, contains, prefix, regex)
    int / time       -> Int
    bool             -> Bool
    ip               -> BitVec(32)  (IPv4; IPv6 literals are handled as approximate atoms)

Every field whose ``exists_bit`` is not ``None`` also gets a Bool *presence* variable, so the
encoders can model "field missing → leaf is False" and the ``Exists`` predicate faithfully.
Fields with ``exists_bit is None`` are always present (their presence term is ``True``).

Repeated fields are represented by a single String standing for *one* element; predicates that
quantify over *all* elements are marked approximate by the predicate encoder.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from decnique.model import event_fields as ef

_ANYCHAR = z3.AllChar(z3.ReSort(z3.SeqSort(z3.CharSort())))


def any_char_star() -> z3.ReRef:
    """Regex matching any run of characters (glob ``*``)."""
    return z3.Star(_ANYCHAR)


def any_char() -> z3.ReRef:
    """Regex matching exactly one character (glob ``?``)."""
    return _ANYCHAR


@dataclass
class SymEvent:
    """A symbolic event: a Z3 term + presence bit per field, created lazily."""

    prefix: str = "e"
    _terms: dict[str, z3.ExprRef] = field(default_factory=dict)
    _present: dict[str, z3.BoolRef] = field(default_factory=dict)

    def _make(self, path: str) -> z3.ExprRef:
        sort = ef.field_sort(path)
        name = f"{self.prefix}.{path}"
        if sort in ("string", "strings"):
            return z3.String(name)
        if sort in ("int", "time"):
            return z3.Int(name)
        if sort == "bool":
            return z3.Bool(name)
        if sort == "ip":
            return z3.BitVec(name, 32)
        return z3.String(name)

    def term(self, path: str) -> z3.ExprRef:
        if path not in self._terms:
            self._terms[path] = self._make(path)
        return self._terms[path]

    def present(self, path: str) -> z3.BoolRef:
        """Presence term: always-``True`` for fields with no exists-bit, else a fresh Bool."""
        if _always_present(path):
            return z3.BoolVal(True)
        if path not in self._present:
            self._present[path] = z3.Bool(f"{self.prefix}.{path}?")
        return self._present[path]

    def sort_of(self, path: str) -> str:
        return ef.field_sort(path)

    def fields(self) -> tuple[str, ...]:
        return tuple(self._terms)


def _always_present(path: str) -> bool:
    # tags.* and udm:* are optional families; a model field is always-present iff no exists-bit.
    return path in ef.EVENT_FIELDS and ef.EVENT_FIELDS[path].exists_bit is None
