"""decnique — a domain-specific language for detections and attacker techniques.

Both a defender's detection rule and an attacker's technique (a *candidate*) are
written against one shared event model, so they can be compared. This package is the
language itself: grammar, parser, AST, formatter, the three-valued interpreter, the
event/predicate/trace model, and the four SIEM front-ends that translate real rules
into the DSL.
"""

from decnique.dsl.parser import DslError, parse_file, parse_text
from decnique.dsl import format as _format
from decnique.dsl.loader import load_paths
from decnique.detections import DetectionLibrary, event_from_audit_log

def format_bundle(b) -> str:
    """Render a parsed :class:`Bundle` back to canonical DSL text."""
    return _format.bundle(b)

__all__ = [
    "DslError",
    "parse_text",
    "parse_file",
    "format_bundle",
    "load_paths",
    "DetectionLibrary",
    "event_from_audit_log",
]
