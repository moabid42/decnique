"""Concrete authorization and predicates for a generated candidate schedule."""

from __future__ import annotations

from decnique.dsl.ast import Candidate, Required
from decnique.dsl.interpret import RefLists, evaluate, field_value
from decnique.env.model import Account
from decnique.eval.trace_eval import matches_footprint


def principal_fields(principal: str) -> dict[str, str]:
    return {
        "principal": principal,
        "principal_type": "SERVICE_ACCOUNT" if principal.endswith(".gserviceaccount.com") else "USER",
    }


def step_requirements(candidate: Candidate, method: str, account: Account) -> tuple[Required, ...]:
    """Declared requirements tied to this method; an empty result needs catalog evidence."""
    permissions = account.catalog.permissions_for(method) or ()
    return tuple(r for r in candidate.required if r.permission in permissions)


def matches_candidate(
    candidate: Candidate, events: tuple[dict, ...] | list[dict], account: Account,
    *, ref_lists: RefLists | None = None,
) -> bool | None:
    """Replay the entire candidate, including actor, context, scoped requirements and Reach.

    Generated schedules contain exactly the expanded footprint in step order. The footprint
    oracle independently checks payload, multiplicity and timing before authorization is tested.
    """
    realized = matches_footprint(candidate.footprint, events, ref_lists=ref_lists)
    if realized is False:
        return False
    steps = [step for step in candidate.footprint.steps for _ in range(max(1, step.repeat))]
    if len(events) != len(steps):
        return False
    results = [realized]
    permissions = tuple(r.permission for r in candidate.required)
    for step, event in zip(steps, events, strict=True):
        principal = str(event.get("principal") or "")
        resource = str(event.get("resource") or "")
        if not resource or resource == "*" or event.get("method") != step.method:
            return False
        if principal not in account.principals_with_all(permissions):
            return False
        if event.get("principal_type") != principal_fields(principal)["principal_type"]:
            return False
        required = step_requirements(candidate, step.method, account)
        if not required:
            results.append(None)
        for req in required:
            if not account.reach(principal, req.permission, resource):
                return False
        predicates = (candidate.actor, candidate.context, step.where, *(r.where for r in required))
        results.extend(evaluate(p, event, ref_lists=ref_lists) for p in predicates if p is not None)
    for path in candidate.share:
        if any(field_value(e, (None, path)) != field_value(events[0], (None, path)) for e in events[1:]):
            return False
    if any(r is False for r in results):
        return False
    return None if any(r is None for r in results) else True
