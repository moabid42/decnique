"""Google SecOps (Chronicle) YARA-L 2.0 front-end (plan §5.16)."""

from __future__ import annotations

from pathlib import Path

from decnique.dsl.ast import Bundle, Detection, LoadIssue
from decnique.frontends.secops.lower import lower_rule
from decnique.frontends.secops.parser import YaralRule, YaralSyntaxError, parse_rules
from decnique.frontends.secops.udm_map import UdmMap, load_udm_map


def load_yaral_text(text: str, file: str, udm: UdmMap | None = None) -> Bundle:
    detections: list[Detection] = []
    issues: list[LoadIssue] = []
    try:
        rules = parse_rules(text)
    except YaralSyntaxError as e:
        return Bundle(issues=(LoadIssue("error", file, f"yaral: {e}"),))
    if not rules:
        return Bundle(issues=(LoadIssue("warning", file, "no `rule` block found"),))
    for rule in rules:
        d = lower_rule(rule, file, udm)
        detections.append(d)
        if d.source and d.source.unsupported:
            issues.append(
                LoadIssue(
                    "warning",
                    file,
                    "unsupported constructs: " + ", ".join(d.source.unsupported),
                    d.id,
                )
            )
    return Bundle(detections=tuple(detections), issues=tuple(issues))


def load_yaral_file(path: Path, udm: UdmMap | None = None) -> Bundle:
    return load_yaral_text(Path(path).read_text(encoding="utf-8"), str(path), udm)


__all__ = [
    "YaralRule",
    "YaralSyntaxError",
    "load_udm_map",
    "load_yaral_file",
    "load_yaral_text",
    "lower_rule",
    "parse_rules",
]
