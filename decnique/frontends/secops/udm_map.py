"""UDM field -> event-model field, from ``catalogs/udm_map.gcp_cloudaudit.v38.json`` (§5.7.4)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from decnique.model import event_fields as ef
from decnique.model.predicates import Cmp, Const, Pred, QField, Value

CATALOG = Path(__file__).resolve().parents[2] / "catalogs" / "udm_map.gcp_cloudaudit.v38.json"


@dataclass(frozen=True, slots=True)
class UdmRow:
    udm: str
    event: str | None  # None => constant field
    transform: str | None
    verified: bool

    @property
    def constant(self) -> str | None:
        if self.transform and self.transform.startswith("const:"):
            return self.transform[len("const:") :]
        return None


@dataclass(frozen=True, slots=True)
class UdmMap:
    version: str
    parser_version: str
    rows: dict[str, UdmRow]

    def lookup(self, udm_path: str) -> UdmRow | None:
        return self.rows.get(udm_path)

    def field(self, udm_path: str) -> tuple[str, UdmRow | None]:
        """Event-model field for a UDM path; unmapped paths become ``udm:<path>`` leaves."""
        row = self.rows.get(udm_path)
        if row is None or row.event is None:
            return ef.udm_field(udm_path), row
        return row.event, row

    def compare(self, var: str | None, udm_path: str, op: str, value: Value, nocase: bool) -> Pred:
        """Lower ``$var.<udm_path> <op> <value>`` to a predicate on the event model."""
        row = self.rows.get(udm_path)
        if row is not None and row.constant is not None and op in {"=", "!="}:
            equal = _eq(str(value), row.constant, nocase)
            return Const(value=equal if op == "=" else not equal)
        field, row = self.field(udm_path)
        value = self.transform_value(row, value, nocase)
        if row is not None and row.transform == "lower":
            nocase = True
        return Cmp(field=(var, field), op=op, value=value, nocase=nocase)  # type: ignore[arg-type]

    @staticmethod
    def transform_value(row: UdmRow | None, value: Value, nocase: bool) -> Value:
        if row is None or row.transform is None:
            return value
        t = row.transform
        if t == "lower" and isinstance(value, str):
            return value.lower()
        if t == "bool" and isinstance(value, str):
            return {"true": True, "false": False}.get(value.lower(), value)
        if t == "action" and isinstance(value, str):
            # security_result.action: ALLOW -> granted, BLOCK -> denied
            return {"allow": True, "block": False}.get(value.lower(), value)
        if t == "account_type" and isinstance(value, str):
            return {"SERVICE_ACCOUNT_TYPE": "SERVICE_ACCOUNT", "CLOUD_ACCOUNT_TYPE": "USER"}.get(
                value, value
            )
        return value

    def qfield(self, var: str | None, udm_path: str) -> QField:
        return (var, self.field(udm_path)[0])


def _eq(a: str, b: str, nocase: bool) -> bool:
    return a.lower() == b.lower() if nocase else a == b


@lru_cache(maxsize=4)
def load_udm_map(path: Path = CATALOG) -> UdmMap:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = {
        r["udm"]: UdmRow(
            r["udm"], r.get("event"), r.get("transform"), bool(r.get("verified", False))
        )
        for r in payload["rows"]
    }
    return UdmMap(str(payload["version"]), str(payload["parser_version"]), rows)
