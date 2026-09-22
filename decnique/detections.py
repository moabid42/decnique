"""DetectionLibrary: the loaded DSL detections, queried on concrete events.

This is the concrete, event-level face of the DSL.  Two questions are answered
exactly against real audit-log data, with no permission bitsets or coverage matrix
involved:

* :meth:`observing` — ``Observes(R, e)``: which detections' predicates accept a
  concrete event (and which are *unknown*, i.e. depend on an untranslatable atom);
* :meth:`admitting` — which detections could involve a given method at all.

(The bitset/SMT permission-coverage layer of the original prototype is intentionally
not part of this package.)
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any as AnyT

from decnique.dsl.ast import Bundle, Detection
from decnique.dsl.interpret import Event, RefLists, admits, observes


@dataclass(frozen=True, slots=True)
class EventObservation:
    """Result of :meth:`DetectionLibrary.observing` for one concrete event."""

    observed_by: tuple[str, ...]  # detections whose predicate accepts the event
    unknown: tuple[str, ...]  # detections whose answer depends on an Unknown atom / absent list
    fires_single: tuple[str, ...]  # observed_by ∩ single-event rules (a one-off action alerts)
    observed: bool
    approximate: bool

    @property
    def unobserved(self) -> bool:
        return not self.observed and not self.unknown


class DetectionLibrary:
    def __init__(self, bundle: Bundle, ref_lists: RefLists | None = None) -> None:
        self.bundle = bundle
        self.ref_lists = ref_lists
        self._by_id = {d.id: d for d in bundle.detections}

    # --- construction ---------------------------------------------------------------------
    @classmethod
    def load(
        cls,
        *paths: Path | str,
        options: LoadOptions | None = None,
        ref_lists: RefLists | None = None,
    ) -> DetectionLibrary:
        from decnique.dsl.loader import load_paths

        return cls(load_paths(paths, options), ref_lists)

    @property
    def detections(self) -> tuple[Detection, ...]:
        return self.bundle.detections

    def get(self, rule_id: str) -> Detection:
        return self._by_id[rule_id]

    def __len__(self) -> int:
        return len(self.bundle.detections)

    def summary(self) -> dict[str, object]:
        from decnique.dsl.loader import summary

        return summary(self.bundle)

    # --- concrete questions --------------------------------------------------------------
    def admitting(
        self, method: str, *, service: str | None = None, permissions: Sequence[str] = ()
    ) -> tuple[Detection, ...]:
        return tuple(
            d
            for d in self.detections
            if admits(d, method, service=service, permissions=permissions)
        )

    def observing(self, event: Event) -> EventObservation:
        observed: list[str] = []
        unknown: list[str] = []
        for d in self.detections:
            r = observes(d, event, ref_lists=self.ref_lists)
            if r is True:
                observed.append(d.id)
            elif r is None:
                unknown.append(d.id)
        fires = tuple(i for i in observed if self._by_id[i].spec.is_single_event)
        return EventObservation(
            observed_by=tuple(observed),
            unknown=tuple(unknown),
            fires_single=fires,
            observed=bool(observed),
            approximate=bool(unknown),
        )


def _epoch(ts: AnyT) -> int | None:
    """A Cloud Audit Log ``timestamp`` (RFC 3339 string, or already epoch seconds) as epoch
    seconds — the model's ``time`` field, which correlation windows/spans read.  Unparseable
    → ``None`` (dropped), so a log without a usable time stays honestly time-less."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return int(ts)
    s = str(ts).strip()
    if not s:
        return None
    try:
        return int(float(s))  # a numeric epoch written as a string
    except ValueError:
        pass
    from datetime import datetime

    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _records(value: AnyT) -> list[Mapping[str, AnyT]]:
    """Mapping records from a repeated audit-log field; malformed members are ignored."""
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _compact(values: Sequence[AnyT]) -> AnyT:
    """Keep a scalar scalar, but never discard later values from a repeated field."""
    kept = [value for value in values if value is not None]
    if len(kept) == 1:
        return kept[0]
    return kept


def _append_flat(out: dict[str, AnyT], path: str, value: AnyT) -> None:
    if value is None:
        return
    if path not in out:
        out[path] = value
        return
    old = out[path]
    if isinstance(old, list):
        old.append(value)
    else:
        out[path] = [old, value]


def _flatten_raw(value: AnyT, path: str, out: dict[str, AnyT]) -> None:
    """Flatten raw JSON leaves to the dotted paths Panther's front-end emits as ``udm``.

    Repeated objects merge into repeated leaf values instead of keeping only their first item.
    """
    if isinstance(value, Mapping):
        for key, child in value.items():
            _flatten_raw(child, f"{path}.{key}" if path else str(key), out)
        return
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for child in value:
            _flatten_raw(child, path, out)
        return
    _append_flat(out, path, value)


def _at(value: AnyT, index: int, *, repeat_scalar: bool = False) -> AnyT:
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return value[index] if index < len(value) else None
    return value if index == 0 or repeat_scalar else None


def _field_values(records: Sequence[Mapping[str, AnyT]], key: str) -> list[AnyT]:
    return [record[key] for record in records if record.get(key) is not None]


def _value_count(value: AnyT) -> int:
    if value is None:
        return 0
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return len(value)
    return 1


_DELTA_PREFIX = "target.resource.attribute.labels[ser_binding_deltas_"
_AUDIT_CONFIG_LABELS = {
    "action": "target.resource.attribute.labels[service_data_policy_delta_audit_config_delta_action]",
    "service": "target.resource.attribute.labels[service_data_policy_delta_audit_config_delta_service]",
    "logType": "target.resource.attribute.labels[service_data_policy_delta_audit_config_delta_log_type]",
    "exemptedMember": "target.resource.attribute.labels[service_data_policy_delta_audit_config_delta_exempted_member]",
}


def event_from_audit_log(entry: Mapping[str, AnyT]) -> dict[str, AnyT]:
    """Normalize a Cloud Audit Log entry onto the concrete event model.

    Canonical fields serve the shared DSL.  Raw request/status/resource/auth leaves are also
    retained as dotted ``udm`` paths, and the Google SecOps policy-delta labels are populated,
    so native-rule replay sees the data that was present in the source record.
    """
    raw_pp = entry.get("protoPayload") or entry
    pp = raw_pp if isinstance(raw_pp, Mapping) else {}
    raw_auth = pp.get("authenticationInfo") or {}
    auth = raw_auth if isinstance(raw_auth, Mapping) else {}
    infos = _records(pp.get("authorizationInfo"))
    raw_meta = pp.get("requestMetadata") or {}
    meta = raw_meta if isinstance(raw_meta, Mapping) else {}
    raw_resource = entry.get("resource") or {}
    monitored = raw_resource if isinstance(raw_resource, Mapping) else {}
    raw_labels = monitored.get("labels") or {}
    labels = raw_labels if isinstance(raw_labels, Mapping) else {}

    permissions = _field_values(infos, "permission")
    resources = _field_values(infos, "resource")
    granted = _field_values(infos, "granted")
    resource_types = [
        attrs["type"]
        for info in infos
        if isinstance((attrs := info.get("resourceAttributes")), Mapping)
        and attrs.get("type") is not None
    ]

    # Preserve the raw shapes that front-ends lower to ``udm:<dotted path>``.  Explicit UDM
    # supplied with the entry wins over a derived value because it is already parser output.
    projected_udm: dict[str, AnyT] = {}
    for key in ("request", "status", "requestMetadata"):
        if key in pp:
            _flatten_raw(pp[key], f"protoPayload.{key}", projected_udm)
    if infos:
        _flatten_raw(infos, "protoPayload.authorizationInfo", projected_udm)
    if labels:
        _flatten_raw(labels, "resource.labels", projected_udm)

    service_data = pp.get("serviceData") or {}
    if isinstance(service_data, Mapping):
        policy_delta = service_data.get("policyDelta") or {}
        if isinstance(policy_delta, Mapping):
            _flatten_raw(
                policy_delta,
                "protoPayload.serviceData.policyDelta",
                projected_udm,
            )
            binding_deltas = _records(policy_delta.get("bindingDeltas"))
            for key in ("action", "role", "member"):
                values = _field_values(binding_deltas, key)
                if values:
                    projected_udm[f"{_DELTA_PREFIX}{key}]"] = _compact(values)
            audit_deltas = _records(policy_delta.get("auditConfigDeltas"))
            for key, udm_path in _AUDIT_CONFIG_LABELS.items():
                values = _field_values(audit_deltas, key)
                if values:
                    projected_udm[udm_path] = _compact(values)

    explicit_udm = entry.get("udm") or {}
    if isinstance(explicit_udm, Mapping):
        projected_udm.update(explicit_udm)

    access_levels: AnyT = None
    request_attrs = meta.get("requestAttributes") or {}
    if isinstance(request_attrs, Mapping):
        request_auth = request_attrs.get("auth") or {}
        if isinstance(request_auth, Mapping):
            access_levels = request_auth.get("accessLevels") or request_auth.get("access_levels")

    principal = str(auth.get("principalEmail", "")).lower() or None
    event: dict[str, AnyT] = {
        "method": pp.get("methodName"),
        "service": pp.get("serviceName"),
        "permission": permissions,
        "principal": principal,
        "principal_type": (
            "SERVICE_ACCOUNT"
            if principal and principal.endswith(".gserviceaccount.com")
            else "USER"
        )
        if principal
        else None,
        "resource": _compact(resources) if resources else pp.get("resourceName"),
        "resource_type": _compact(resource_types),
        "project": labels.get("project_id"),
        "caller_ip": meta.get("callerIp"),
        "user_agent": meta.get("callerSuppliedUserAgent"),
        "granted": _compact(granted),
        "time": _epoch(entry.get("timestamp") or pp.get("timestamp")),
        "log_name": entry.get("logName"),
        "access_levels": access_levels,
        "udm": projected_udm,
    }
    return {k: v for k, v in event.items() if v is not None and v != []}


def to_audit_log(event: Mapping[str, AnyT]) -> dict[str, AnyT]:
    """The inverse of :func:`event_from_audit_log`: a witness as a Cloud Audit Log entry
    (``protoPayload`` form) that can be replayed in a SIEM.  Model fields land where the log
    keeps them; IAM binding deltas go to ``serviceData.policyDelta.bindingDeltas``; any other
    ``udm`` field is kept under ``udm`` (it has no fixed place in the raw record)."""
    e = dict(event)
    pp: dict[str, AnyT] = {"@type": "type.googleapis.com/google.cloud.audit.AuditLog"}
    if e.get("method"):
        pp["methodName"] = e["method"]
    if e.get("service"):
        pp["serviceName"] = e["service"]
    if e.get("principal"):
        pp["authenticationInfo"] = {"principalEmail": e["principal"]}
    perms = e.get("permission")
    granted = e.get("granted")
    resources = e.get("resource")
    resource_types = e.get("resource_type")
    auth_count = max(
        _value_count(perms),
        _value_count(granted),
        _value_count(resources),
        _value_count(resource_types),
    )
    if auth_count:
        infos: list[dict[str, AnyT]] = []
        for index in range(auth_count):
            info: dict[str, AnyT] = {}
            permission = _at(perms, index)
            allowed = _at(granted, index, repeat_scalar=True)
            resource = _at(resources, index, repeat_scalar=True)
            resource_type = _at(resource_types, index, repeat_scalar=True)
            if permission is not None:
                info["permission"] = permission
            if allowed is not None:
                info["granted"] = bool(allowed)
            if resource is not None:
                info["resource"] = resource
            if resource_type is not None:
                info["resourceAttributes"] = {"type": resource_type}
            infos.append(info)
        pp["authorizationInfo"] = infos
    resource_name = _at(resources, 0)
    if resource_name:
        pp["resourceName"] = resource_name
    meta = {}
    if e.get("caller_ip"):
        meta["callerIp"] = e["caller_ip"]
    if e.get("user_agent"):
        meta["callerSuppliedUserAgent"] = e["user_agent"]
    if meta:
        pp["requestMetadata"] = meta
    udm = dict(e.get("udm") or {})
    binding_fields = {
        key: udm.pop(f"{_DELTA_PREFIX}{key}]")
        for key in ("action", "role", "member")
        if f"{_DELTA_PREFIX}{key}]" in udm
    }
    binding_count = max((_value_count(value) for value in binding_fields.values()), default=0)
    binding_deltas = []
    for index in range(binding_count):
        delta = {
            key: item
            for key, value in binding_fields.items()
            if (item := _at(value, index, repeat_scalar=True)) is not None
        }
        if delta:
            binding_deltas.append(delta)

    audit_fields = {
        key: udm.pop(path)
        for key, path in _AUDIT_CONFIG_LABELS.items()
        if path in udm
    }
    audit_count = max((_value_count(value) for value in audit_fields.values()), default=0)
    audit_deltas = []
    for index in range(audit_count):
        delta = {
            key: item
            for key, value in audit_fields.items()
            if (item := _at(value, index, repeat_scalar=True)) is not None
        }
        if delta:
            audit_deltas.append(delta)
    if binding_deltas or audit_deltas:
        policy_delta: dict[str, AnyT] = {}
        if binding_deltas:
            policy_delta["bindingDeltas"] = binding_deltas
        if audit_deltas:
            policy_delta["auditConfigDeltas"] = audit_deltas
        pp["serviceData"] = {"policyDelta": policy_delta}
    entry: dict[str, AnyT] = {"protoPayload": pp}
    if e.get("log_name"):
        entry["logName"] = e["log_name"]
    if e.get("project"):
        entry["resource"] = {"labels": {"project_id": e["project"]}}
    if "time" in e:
        entry["timestamp"] = e["time"]
    if udm:
        entry["udm"] = udm
    return entry


# re-export for callers that used to import these names from this module
from decnique.dsl.loader import LoadOptions  # noqa: E402
