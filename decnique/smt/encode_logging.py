"""The same category/scope/exemption formula for symbolic traces and atom-based coverage."""

from __future__ import annotations

from fnmatch import fnmatchcase

import z3

from decnique.env.model import DATA_ACCESS_TYPES, Account
from decnique.model.predicates import Cmp, Like
from decnique.smt.encode_pred import Encoder


def logging_constraint(enc: Encoder, account: Account, method: str) -> z3.BoolRef:
    """Encode Log; unsupported scope classes remain proposals, never proof-supporting facts."""
    if account.logging.audit_configs is None or not account.catalog.is_data_access(method):
        return z3.BoolVal(account.logged(method))
    if method in account.logging.disabled_methods:
        return z3.BoolVal(False)

    def scope(pattern: str) -> z3.BoolRef:
        if pattern == "*":
            return z3.BoolVal(True)
        if "[" in pattern:
            return z3.FreshBool("audit.scope")  # logging_caveats prevents an exact verdict
        direct = enc.pred(Like(field=(None, "resource"), pattern=pattern.replace("\\", "\\\\")))
        descendants = [enc.pred(Cmp(field=(None, "resource"), op="=", value=child))
                       for child in account.hierarchy
                       if any(fnmatchcase(parent, pattern) for parent in account._ancestors(child)[1:])]
        return z3.Or(direct, *descendants)

    configs = [(c, scope(c.resource)) for c in account.audit_configs_for(method)]
    categories = []
    for category in DATA_ACCESS_TYPES:
        enabled = [sc for c, sc in configs if c.log_type == category]
        exempt = [z3.And(sc, enc.pred(Cmp(field=(None, "principal"), op="=", value=p)))
                  for c, sc in configs if c.log_type == category for p in c.exempted_members]
        categories.append(z3.And(z3.Or(*enabled), z3.Not(z3.Or(*exempt))))
    return z3.Or(*categories)
