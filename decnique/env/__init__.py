"""Environment / account model (plan §M1): the infra constraints ``Reach`` and ``Log``.

Coverage answers are always relative to a specific account (Invariant #2): a blind spot is
real only if the attacker can cause the event *and* it is logged.  This package supplies
that account model and the method↔permission catalog that connects a rule's ``method``
world to the account's ``permission`` world.
"""

from __future__ import annotations

from decnique.env.catalog import Catalog, MethodInfo
from decnique.env.ingest import AccountSchemaError, account_from_dict, load_account
from decnique.env.model import Account, Deny, Grant, LogConfig

__all__ = [
    "Account",
    "AccountSchemaError",
    "Catalog",
    "Deny",
    "Grant",
    "LogConfig",
    "MethodInfo",
    "account_from_dict",
    "load_account",
]
