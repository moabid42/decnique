"""Elastic detection-rules front-end: TOML rules -> DSL detections.

``type = "query"`` rules with ``language = "kuery"`` are lowered through a small KQL
parser (``field:value``, ``field:(a or b and not c)``, ``field:*``, wildcards,
ranges, ``and``/``or``/``not``).  ``esql``, ``eql``, ``machine_learning``,
``new_terms`` and ``threshold`` rules are not expressible as single-event
predicates and lower to ``Unknown`` atoms (``new_terms`` keeps its base query).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any as AnyT

from decnique.dsl.ast import Bundle, Detection, LoadIssue, Provenance
from decnique.model import event_fields as ef
from decnique.model.predicates import (
    Cmp,
    Const,
    Exists,
    Like,
    Not,
    Pred,
    Unknown,
    all_of,
    any_of,
)
from decnique.model.trace import single_event

FIELD_MAP: dict[str, str] = {
    "event.action": "method",
    "event.outcome": "granted",
    "user.email": "principal",
    "user.name": "principal",
    "client.user.email": "principal",
    "client.user.name": "principal",
    "source.ip": "caller_ip",
    "client.ip": "caller_ip",
    "user_agent.original": "user_agent",
    "gcp.audit.resource_name": "resource",
    "gcp.audit.type": "resource_type",
    "service.name": "service",
    "gcp.audit.authorization_info.permission": "permission",
    "gcp.audit.authorization_info.granted": "granted",
    "gcp.audit.authentication_info.principal_email": "principal",
    "gcp.audit.method_name": "method",
}
_DATASET_FIELDS = {
    "data_stream.dataset",
    "event.dataset",
    "event.module",
    "event.kind",
    "event.category",
}


def is_elastic_gcp(doc: dict[str, AnyT]) -> bool:
    meta, rule = doc.get("metadata") or {}, doc.get("rule") or {}
    integ = meta.get("integration") or []
    if isinstance(integ, str):
        integ = [integ]
    if any(str(i).lower() == "gcp" for i in integ):
        return True
    idx = rule.get("index") or []
    return any("gcp" in str(i).lower() for i in idx) or "gcp.audit" in str(rule.get("query", ""))


def load_elastic_text(
    text: str, file: str, *, gcp_only: bool = True, include_deprecated: bool = False
) -> Bundle:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return Bundle(issues=(LoadIssue("error", file, f"elastic toml: {e}"),))
    rule = doc.get("rule")
    if not isinstance(rule, dict) or "name" not in rule:
        return Bundle()
    if gcp_only and not is_elastic_gcp(doc):
        return Bundle()
    maturity = str((doc.get("metadata") or {}).get("maturity", "production"))
    if maturity == "deprecated" and not include_deprecated:
        return Bundle()
    d, unsupported = lower_elastic(doc, file)
    issues = ()
    if unsupported:
        issues = (
            LoadIssue("warning", file, "unsupported constructs: " + ", ".join(unsupported), d.id),
        )
    return Bundle(detections=(d,), issues=issues)


def load_elastic_file(path: Path, **kw: AnyT) -> Bundle:
    return load_elastic_text(Path(path).read_text(encoding="utf-8"), str(path), **kw)


def elastic_id(rule: dict[str, AnyT], file: str) -> str:
    raw = str(rule.get("rule_id") or Path(file).stem)
    return "elastic_" + re.sub(r"[^A-Za-z0-9_]", "_", raw)


def lower_elastic(doc: dict[str, AnyT], file: str) -> tuple[Detection, list[str]]:
    rule = doc["rule"]
    unsupported: list[str] = []
    rtype = str(rule.get("type", "query"))
    language = str(rule.get("language", "kuery"))
    query = str(rule.get("query", "")).strip()
    if rtype in {"query", "new_terms", "threshold"} and language == "kuery" and query:
        pred = parse_kql(query, unsupported)
        if rtype == "new_terms":
            unsupported.append("elastic:new_terms")
            pred = all_of(
                [
                    pred,
                    Unknown(
                        label="elastic:new_terms",
                        raw=",".join(
                            (rule.get("new_terms") or {}).get("field", [])
                            if isinstance(rule.get("new_terms"), dict)
                            else []
                        ),
                    ),
                ]
            )
        elif rtype == "threshold":
            unsupported.append("elastic:threshold")
            pred = all_of(
                [pred, Unknown(label="elastic:threshold", raw=str(rule.get("threshold")))]
            )
    else:
        label = f"elastic:{rtype}:{language}" if rtype == "query" else f"elastic:{rtype}"
        unsupported.append(label)
        pred = Unknown(label=label, raw=query[:200] or str(rule.get("machine_learning_job_id", "")))
    meta: dict[str, str | int | bool] = {
        "source": "elastic",
        "title": str(rule.get("name", "")),
        "type": rtype,
    }
    for key in ("severity", "risk_score", "description", "license"):
        if key in rule and rule[key] is not None:
            meta[key] = rule[key] if isinstance(rule[key], int | bool) else str(rule[key])
    threat = rule.get("threat") or []
    techniques: list[str] = []
    for t in threat:
        for tech in t.get("technique") or []:
            techniques.append(str(tech.get("id", "")))
            for sub in tech.get("subtechnique") or []:
                techniques.append(str(sub.get("id", "")))
    if techniques:
        meta["mitre_attack_technique_id"] = ",".join(techniques)
    md = doc.get("metadata") or {}
    if md.get("maturity"):
        meta["maturity"] = str(md["maturity"])
    return (
        Detection(
            id=elastic_id(rule, file),
            spec=single_event("e", pred),
            meta=meta,
            source=Provenance(
                file=file,
                frontend="elastic",
                native_id=str(rule.get("rule_id", "")),
                unsupported=tuple(dict.fromkeys(unsupported)),
            ),
        ),
        unsupported,
    )


# --- KQL ------------------------------------------------------------------------------------------

_KQL_TOK = re.compile(
    r"""
    (?P<WS>\s+)
  | (?P<STR>"(?:[^"\\]|\\.)*")
  | (?P<OP>\(|\)|:|<=|>=|<|>)
  | (?P<TERM>(?:\\.|[^\s()":<>])+)
    """,
    re.X,
)


def parse_kql(text: str, unsupported: list[str]) -> Pred:
    toks: list[tuple[str, str]] = []
    for m in _KQL_TOK.finditer(text):
        kind = m.lastgroup or ""
        if kind != "WS":
            toks.append((kind, m.group(0)))
    p = _Kql(toks, unsupported)
    try:
        pred = p.query()
        if p.i != len(toks):
            raise ValueError(f"trailing tokens at {toks[p.i][1]!r}")
        return pred
    except ValueError as e:
        unsupported.append(f"kql:{e}")
        return Unknown(label="elastic:kql", raw=text[:200])


class _Kql:
    def __init__(self, toks: list[tuple[str, str]], unsupported: list[str]) -> None:
        self.toks, self.i, self.unsupported = toks, 0, unsupported

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def is_kw(self, kw: str) -> bool:
        t = self.peek()
        return t is not None and t[0] == "TERM" and t[1].lower() == kw

    def take(self) -> tuple[str, str]:
        t = self.peek()
        if t is None:
            raise ValueError("unexpected end")
        self.i += 1
        return t

    def query(self) -> Pred:
        parts = [self.and_()]
        while self.is_kw("or"):
            self.i += 1
            parts.append(self.and_())
        return any_of(parts)

    def and_(self) -> Pred:
        parts = [self.not_()]
        while self.is_kw("and"):
            self.i += 1
            parts.append(self.not_())
        return all_of(parts)

    def not_(self) -> Pred:
        if self.is_kw("not"):
            self.i += 1
            return Not(child=self.not_())
        return self.atom()

    def atom(self) -> Pred:
        kind, text = self.take()
        if kind == "OP" and text == "(":
            q = self.query()
            if self.take() != ("OP", ")"):
                raise ValueError("expected )")
            return q
        if kind not in {"TERM", "STR"}:
            raise ValueError(f"unexpected {text!r}")
        nxt = self.peek()
        if nxt is None or nxt[0] != "OP" or nxt[1] == "(" or nxt[1] == ")":
            self.unsupported.append("kql:free_text")
            return Unknown(label="elastic:kql_free_text", raw=text)
        op = self.take()[1]
        field = _unescape(text)
        if op == ":":
            return self.values(field)
        _, vtext = self.take()
        return _leaf(field, op, _unescape(vtext), self.unsupported)

    def values(self, field: str) -> Pred:
        t = self.peek()
        if t == ("OP", "("):
            self.i += 1
            pred = self.vor(field)
            if self.take() != ("OP", ")"):
                raise ValueError("expected ) in value group")
            return pred
        kind, text = self.take()
        if kind not in {"TERM", "STR"}:
            raise ValueError(f"expected value after {field}:")
        return _leaf(field, ":", _unescape(text), self.unsupported)

    def vor(self, field: str) -> Pred:
        parts = [self.vand(field)]
        while self.is_kw("or"):
            self.i += 1
            parts.append(self.vand(field))
        return any_of(parts)

    def vand(self, field: str) -> Pred:
        parts = [self.vnot(field)]
        while self.is_kw("and"):
            self.i += 1
            parts.append(self.vnot(field))
        return all_of(parts)

    def vnot(self, field: str) -> Pred:
        if self.is_kw("not"):
            self.i += 1
            return Not(child=self.vnot(field))
        t = self.peek()
        if t == ("OP", "("):
            self.i += 1
            p = self.vor(field)
            if self.take() != ("OP", ")"):
                raise ValueError("expected )")
            return p
        kind, text = self.take()
        if kind not in {"TERM", "STR"}:
            raise ValueError(f"unexpected {text!r} in value group")
        return _leaf(field, ":", _unescape(text), self.unsupported)


def _unescape(t: str) -> str:
    if t.startswith('"') and t.endswith('"') and len(t) >= 2:
        return re.sub(r"\\(.)", r"\1", t[1:-1])
    return re.sub(r"\\(.)", r"\1", t)


def _leaf(field: str, op: str, value: str, unsupported: list[str]) -> Pred:
    low = field.lower()
    if low in _DATASET_FIELDS and re.search(r"\bgcp\b|google[._-]?cloud", value, re.I):
        return Const(value=True)  # the GCP audit dataset is implied by the loader's scope
    # any other dataset/module value is an ordinary equality on the raw field — it must NOT
    # collapse to `true`, or the rule would "cover" every event (docs/COVERAGE_ABSTRACTION.md §1)
    path = FIELD_MAP.get(low, ef.udm_field(field))
    qf = (None, path)
    if op != ":":
        try:
            return Cmp(field=qf, op=op, value=int(value))  # type: ignore[arg-type]
        except ValueError:
            return Cmp(field=qf, op=op, value=value)  # type: ignore[arg-type]
    if value == "*":
        return Exists(field=qf)
    if path == "granted":
        mapped = {"success": True, "failure": False, "true": True, "false": False}.get(
            value.lower()
        )
        if mapped is not None:
            return Cmp(field=qf, op="=", value=mapped)
    if "*" in value or "?" in value:
        return Like(field=qf, pattern=value, nocase=True)
    if value.lower() in {"true", "false"} and path not in {"method", "principal", "resource"}:
        return Cmp(field=qf, op="=", value=value.lower() == "true")
    return Cmp(field=qf, op="=", value=value, nocase=True)


__all__ = [
    "FIELD_MAP",
    "is_elastic_gcp",
    "load_elastic_file",
    "load_elastic_text",
    "lower_elastic",
    "parse_kql",
]
