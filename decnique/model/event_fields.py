"""The closed list of event-model fields usable in the DSL (plan §5.3).

Every field names a Cloud Audit Log attribute of one event (the §3.1 context).  Two
open families are also accepted: ``tags.<key>`` (resource tags) and ``udm:<path>``
(a raw UDM field with no event-model interpretation; lowers to an uninterpreted atom).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Sort = Literal["string", "int", "bool", "ip", "time", "strings"]


@dataclass(frozen=True, slots=True)
class FieldSpec:
    name: str
    sort: Sort
    exists_bit: str | None  # which exists-bit guards the field; None = always present
    repeated: bool = False
    doc: str = ""


_FIELDS: tuple[FieldSpec, ...] = (
    FieldSpec("method", "string", None, doc="protoPayload.methodName"),
    FieldSpec("service", "string", None, doc="service(method) from the catalog / serviceName"),
    FieldSpec("permission", "string", None, True, "authorizationInfo[].permission"),
    FieldSpec("principal", "string", "principal_exists", doc="authenticationInfo.principalEmail"),
    FieldSpec("principal_type", "string", "principal_exists", doc="SERVICE_ACCOUNT | USER"),
    FieldSpec("resource", "string", None, doc="authorizationInfo[].resource, normalized"),
    FieldSpec("resource_type", "string", None, doc="resourceAttributes.type"),
    FieldSpec("project", "string", None, doc="ancestry of resource"),
    FieldSpec("folder", "string", None, True, "ancestry of resource"),
    FieldSpec("org", "string", None, doc="ancestry of resource"),
    FieldSpec("caller_ip", "ip", "caller_ip_exists", doc="requestMetadata.callerIp"),
    FieldSpec("user_agent", "string", "user_agent_exists", doc="callerSuppliedUserAgent"),
    FieldSpec("granted", "bool", None, doc="authorizationInfo[].granted"),
    FieldSpec("time", "time", None, doc="request time, epoch seconds"),
    FieldSpec("event_type", "string", None, doc="UDM metadata.event_type (derived)"),
    FieldSpec("product_name", "string", None, doc="UDM metadata.product_name (derived)"),
    FieldSpec("log_name", "string", None, doc="logName: activity vs data_access"),
    FieldSpec("access_levels", "strings", None, True, "request.auth.access_levels"),
    FieldSpec("sent_bytes", "int", None, doc="numeric UDM field for aggregates"),
    FieldSpec("received_bytes", "int", None, doc="numeric UDM field for aggregates"),
)

EVENT_FIELDS: dict[str, FieldSpec] = {f.name: f for f in _FIELDS}
FIELD_NAMES: tuple[str, ...] = tuple(EVENT_FIELDS)

# Fields whose value is fixed per query or per method and therefore resolved in Python
# rather than in the solver (plan §5.3, §5.11 `admits`).
METHOD_LEVEL_FIELDS: frozenset[str] = frozenset({"method", "service", "permission"})

UDM_PREFIX = "udm:"
TAG_PREFIX = "tags."


def is_known_field(path: str) -> bool:
    return path in EVENT_FIELDS or path.startswith(TAG_PREFIX) or path.startswith(UDM_PREFIX)


def field_sort(path: str) -> Sort:
    if path in EVENT_FIELDS:
        return EVENT_FIELDS[path].sort
    return "string"


def is_repeated(path: str) -> bool:
    return path in EVENT_FIELDS and EVENT_FIELDS[path].repeated


def udm_field(path: str) -> str:
    return UDM_PREFIX + path


def is_udm(path: str) -> bool:
    return path.startswith(UDM_PREFIX)


def udm_path(path: str) -> str:
    return path.removeprefix(UDM_PREFIX)


def describe_fields() -> str:
    return ", ".join(FIELD_NAMES) + ', tags.<key>, udm("<path>")'
