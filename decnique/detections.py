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
        options: "LoadOptions | None" = None,
        ref_lists: RefLists | None = None,
    ) -> "DetectionLibrary":
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


def event_from_audit_log(entry: Mapping[str, AnyT]) -> dict[str, AnyT]:
    """Project a Cloud Audit Log entry (``protoPayload`` form) onto the event model."""
    pp = entry.get("protoPayload") or entry
    auth = pp.get("authenticationInfo") or {}
    infos = pp.get("authorizationInfo") or []
    meta = pp.get("requestMetadata") or {}
    first = infos[0] if infos else {}
    principal = str(auth.get("principalEmail", "")).lower() or None
    event: dict[str, AnyT] = {
        "method": pp.get("methodName"),
        "service": pp.get("serviceName"),
        "permission": [i.get("permission") for i in infos if i.get("permission")],
        "principal": principal,
        "principal_type": (
            "SERVICE_ACCOUNT"
            if principal and principal.endswith(".gserviceaccount.com")
            else "USER"
        )
        if principal
        else None,
        "resource": first.get("resource") or pp.get("resourceName"),
        "resource_type": ((first.get("resourceAttributes") or {}).get("type")),
        "caller_ip": meta.get("callerIp"),
        "user_agent": meta.get("callerSuppliedUserAgent"),
        "granted": first.get("granted") if infos else None,
        "log_name": entry.get("logName"),
        "udm": dict(entry.get("udm") or {}),
    }
    return {k: v for k, v in event.items() if v is not None and v != []}


# re-export for callers that used to import these names from this module
from decnique.dsl.loader import LoadOptions  # noqa: E402
