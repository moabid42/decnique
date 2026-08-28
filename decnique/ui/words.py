"""Plain-English wording for blindspots — ``config blindspots.explain words``.

*** HARD-CODED, DELIBERATELY LIMITED ***

Everything in this module is a hand-written phrase table.  It knows exactly one family of
fields — the GCP IAM binding deltas (``action`` / ``role`` / ``member`` of a SetIamPolicy
event) — and a handful of literal patterns that appear in the vendored corpus.  Anything
else falls back to the rule's own syntax.  It exists because a sentence like *"someone grants
the Owner role to a service account"* reads better than the atoms, but it does **not**
generalise: a new field, a new role pattern, or a non-IAM permission gets no wording here.

The two data-driven modes (``rules`` — the rules' own titles and tests from the UNSAT core;
``formula`` — the blind region as proven cubes) need none of this and are the defaults.
Extend the tables below if you want more sentences; do not expect them to be complete.
"""

from __future__ import annotations

from decnique.smt.coverage import describe_atom

# the only field family this module understands
_DELTA = "udm:target.resource.attribute.labels[ser_binding_deltas_{}]"

# literal patterns seen in the corpus -> words.  HARD-CODED; extend by hand.
_ROLE_WORDS = {
    "roles/owner": "the Owner role",
    "roles/*Admin": "an …Admin role",
    "roles/owner.*|roles/editor.*": "Owner or Editor",
    "roles/storage.*": "a Storage role",
}
_MEMBER_WORDS = {
    "^serviceAccount": "to a service account",
    ".*@gmail\\.com|.*@googlemail\\.com|.*@googlegroups\\.com": "to a gmail / googlegroups account",
    "allUsers|allAuthenticatedUsers": "to everyone (public)",
}
_ACTION_WORDS = {"ADD": "grants", "REMOVE": "revokes"}


def words_for(atom) -> str | None:  # type: ignore[no-untyped-def]
    """Plain words for one IAM binding-delta atom; ``None`` for any other field."""
    f, lit = atom.field, atom.text
    if f == _DELTA.format("action"):
        return _ACTION_WORDS.get(lit)
    if f == _DELTA.format("role"):
        return _ROLE_WORDS.get(lit) or (f"the role {lit}" if atom.kind == "eq" else f"a role matching {lit}")
    if f == _DELTA.format("member"):
        if lit.startswith("user:"):
            return f"to {lit}"
        return _MEMBER_WORDS.get(lit) or f"to a member matching {lit}"
    return None


def change_sentence(v) -> str:  # type: ignore[no-untyped-def]
    """A kind of change as a sentence when every atom is understood; else the rules' syntax."""
    parts = [words_for(a) for a in v.atoms]
    if parts and all(parts):
        verb = next((p for p in parts if p in _ACTION_WORDS.values()), "grants or revokes")
        role = next((p for p in parts if p.startswith(("the ", "an ", "a ", "Owner"))), "any role")
        member = next((p for p in parts if p.startswith("to ")), "to anyone")
        return f"someone {verb} {role} {member}"
    return "an event where " + "  and  ".join(describe_atom(a) for a in v.atoms)


def event_sentence(ev: dict) -> str:
    """A witness as a sentence — real wording only for IAM policy changes."""
    who, method = ev.get("principal", "someone"), ev.get("method", "?")
    udm = ev.get("udm") or {}
    d = {k: udm.get(_DELTA.format(k)[4:]) for k in ("action", "role", "member")}
    if d["action"]:
        verb = _ACTION_WORDS.get(d["action"], d["action"])
        return f"{who} calls {method} and {verb} {d['role'] or 'a role'} to/from {d['member'] or 'someone'}"
    return f"{who} calls {method}"
