"""Files and directories -> :class:`Bundle` (plan §5.10 ``loader.py``).

Accepts native ``.decn`` files and, through the front-ends, the vendored corpora
under ``IAMouflage/data/detections`` (Google SecOps ``.yaral``, Sigma ``.yml``,
Elastic ``.toml``, Panther ``.yml``+``.py``).  Files are recognised by content, not
by directory name, so any layout works.  Rulesets resolve ``include`` globs relative
to the file that declares them and apply ``disable``/``enable``.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from pathlib import Path

from decnique.dsl.ast import Bundle, Detection, LoadIssue, Ruleset
from decnique.dsl.parser import DslError, ParseOptions, parse_text
from decnique.frontends import elastic, panther, sigma
from decnique.frontends.secops import load_yaral_text

FRONTENDS = ("dsl", "secops", "sigma", "elastic", "panther", "ast")
_SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "tests",
    "test",
    "docs",
    "tools",
    "scripts",
    "_deprecated",
}
_SKIP_DIRS_KEEP_DEPRECATED = _SKIP_DIRS - {"_deprecated"}


@dataclass(frozen=True, slots=True)
class LoadOptions:
    gcp_only: bool = True
    include_deprecated: bool = False
    frontends: tuple[str, ...] = FRONTENDS
    parse: ParseOptions = ParseOptions()
    max_file_bytes: int = 2_000_000


def sniff(path: Path, text: str | None = None) -> str | None:
    """Which front-end handles this file, or ``None``."""
    suffix = path.suffix.lower()
    if suffix == ".decn":
        return "dsl"
    if suffix == ".yaral":
        return "secops"
    if text is None:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
    if suffix == ".toml":
        return "elastic" if re.search(r"^\[rule\]", text, re.M) else None
    if suffix in {".yml", ".yaml"}:
        head = text[:4000]
        if re.search(r"^AnalysisType:\s*(rule|correlation_rule|scheduled_rule)\b", head, re.M):
            return "panther"
        if re.search(r"^logsource:", head, re.M) and re.search(r"^detection:", text, re.M):
            return "sigma"
        if re.search(r"^detections:\s*$", head, re.M) and re.search(
            r"^\s*-\s*kind:\s*detection", head, re.M
        ):
            return "ast"
        return None
    if suffix == ".json" and text.lstrip().startswith("{") and '"detections"' in text[:200]:
        return "ast"
    return None


def load_file(path: Path, options: LoadOptions | None = None) -> Bundle:
    options = options or LoadOptions()
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return Bundle()
    kind = sniff(path, text)
    if kind is None or kind not in options.frontends:
        return Bundle()
    try:
        if kind == "dsl":
            return parse_text(text, str(path), options.parse)
        if kind == "secops":
            if (
                options.gcp_only
                and "gcp" not in {p.lower() for p in path.parts}
                and not re.search(r"gcp|google cloud", text, re.I)
            ):
                return Bundle()
            b = load_yaral_text(text, str(path))
            if options.gcp_only:
                b = _filter_secops_gcp(b, path)
            return b
        if kind == "sigma":
            return sigma.load_sigma_text(text, str(path), gcp_only=options.gcp_only)
        if kind == "elastic":
            if options.gcp_only and "gcp" not in text.lower():
                return Bundle()
            return elastic.load_elastic_text(
                text,
                str(path),
                gcp_only=options.gcp_only,
                include_deprecated=options.include_deprecated,
            )
        if kind == "panther":
            return panther.load_panther_file(path, gcp_only=options.gcp_only, text=text)
        if kind == "ast":
            from decnique.dsl import yaml_io

            return yaml_io.load(path)
    except DslError as e:
        return Bundle(issues=(LoadIssue("error", str(path), e.message),))
    except (
        OSError,
        UnicodeDecodeError,
        ValueError,
    ) as e:  # front-ends degrade; a crash is a load error
        return Bundle(issues=(LoadIssue("error", str(path), f"{kind}: {e}"),))
    return Bundle()


def _filter_secops_gcp(b: Bundle, path: Path) -> Bundle:
    if "gcp" in {p.lower() for p in path.parts}:
        return b
    keep = tuple(
        d
        for d in b.detections
        if "gcp" in str(d.meta.get("platform", "")).lower()
        or "google cloud" in str(d.meta.get("platform", "")).lower()
        or "gcp" in str(d.meta.get("data_source", "")).lower()
    )
    return replace(b, detections=keep)


def iter_files(root: Path, options: LoadOptions | None = None) -> Iterable[Path]:
    options = options or LoadOptions()
    skip = _SKIP_DIRS_KEEP_DEPRECATED if options.include_deprecated else _SKIP_DIRS
    root = Path(root)
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in skip for part in p.relative_to(root).parts[:-1]):
            continue
        if (
            p.suffix.lower() in {".decn", ".yaral", ".toml", ".yml", ".yaml", ".json"}
            and p.stat().st_size <= options.max_file_bytes
        ):
            yield p


def load_paths(paths: Iterable[Path | str], options: LoadOptions | None = None) -> Bundle:
    """Load every recognised file under the given files/directories, then resolve rulesets
    and reject duplicate ids."""
    options = options or LoadOptions()
    bundle = Bundle()
    for p in paths:
        p = Path(p)
        if not p.exists():
            bundle += Bundle(issues=(LoadIssue("error", str(p), "path does not exist"),))
            continue
        for f in iter_files(p, options):
            bundle += load_file(f, options)
    bundle = _apply_rulesets(bundle, options)
    return _dedupe_ids(bundle)


def load_corpus(root: Path | str, options: LoadOptions | None = None) -> Bundle:
    """Load the vendored detection corpora (``IAMouflage/data/detections``)."""
    return load_paths([root], options)


def _apply_rulesets(bundle: Bundle, options: LoadOptions) -> Bundle:
    if not bundle.rulesets:
        return bundle
    extra = Bundle()
    disabled: set[str] = set()
    enabled: set[str] = set()
    for rs in bundle.rulesets:
        base = _ruleset_dir(bundle, rs)
        for pattern in rs.includes:
            matched = sorted(base.glob(pattern)) if base else []
            if not matched:
                extra += Bundle(
                    issues=(
                        LoadIssue(
                            "warning",
                            str(base / pattern) if base else pattern,
                            f"ruleset {rs.id}: include matches no file",
                        ),
                    )
                )
            for f in matched:
                if f.is_file():
                    extra += load_file(f, options)
        disabled |= rs.disabled
        enabled |= rs.enabled
    merged = bundle + extra
    if disabled or enabled:
        kept = tuple(d for d in merged.detections if d.id not in disabled or d.id in enabled)
        missing = [x for x in disabled | enabled if not any(d.id == x for d in merged.detections)]
        issues = tuple(
            LoadIssue("warning", "<ruleset>", f"disable/enable names unknown rule {x}")
            for x in missing
        )
        merged = replace(merged, detections=kept, issues=merged.issues + issues)
    return merged


def _ruleset_dir(bundle: Bundle, rs: Ruleset) -> Path | None:
    # rulesets do not carry provenance; finding the .decn file that declares them is
    # unreliable, so include globs resolve relative to the first .decn file loaded or the cwd.
    for d in bundle.detections:
        if d.source and d.source.frontend == "dsl":
            return Path(d.source.file).parent
    return Path.cwd()


def _dedupe_ids(bundle: Bundle) -> Bundle:
    """Collapse repeats within a single load, for every id'd kind (detections, candidates,
    checks, rulesets).  An id that repeats with *identical* content — the same item reached
    twice, e.g. a file named directly and also under a directory — is silently collapsed to
    one.  An id that repeats with *different* content is a real clash: the first is kept and
    an error is recorded.  Provenance (which file a rule came from) is ignored when deciding
    "identical", so the same rule vendored in two places collapses instead of clashing."""
    issues = list(bundle.issues)

    def dedupe(items: tuple, kind: str, content) -> tuple:
        seen: dict[str, object] = {}
        kept: list = []
        for it in items:
            prev = seen.get(it.id)
            if prev is None:
                seen[it.id] = it
                kept.append(it)
            elif content(prev) == content(it):
                continue  # same item loaded twice — collapse silently
            else:
                here = getattr(getattr(it, "source", None), "file", None) or "<unknown>"
                first = getattr(getattr(prev, "source", None), "file", None) or "<unknown>"
                issues.append(
                    LoadIssue("error", here, f"duplicate {kind} id {it.id} (first seen in {first})", it.id)
                )
        return tuple(kept)

    return replace(
        bundle,
        detections=dedupe(bundle.detections, "detection", lambda d: replace(d, source=None)),
        candidates=dedupe(bundle.candidates, "candidate", lambda c: c),
        checks=dedupe(bundle.checks, "check", lambda c: c),
        rulesets=dedupe(bundle.rulesets, "ruleset", lambda r: r),
        issues=tuple(issues),
    )


def select(
    bundle: Bundle, *, frontend: str | None = None, pattern: str | None = None
) -> tuple[Detection, ...]:
    out = bundle.detections
    if frontend:
        out = tuple(d for d in out if d.source and d.source.frontend == frontend)
    if pattern:
        out = tuple(d for d in out if fnmatch.fnmatchcase(d.id, pattern))
    return out


def summary(bundle: Bundle) -> dict[str, object]:
    by_frontend: dict[str, int] = {}
    approximate = 0
    correlation = 0
    for d in bundle.detections:
        fe = d.source.frontend if d.source else "dsl"
        by_frontend[fe] = by_frontend.get(fe, 0) + 1
        approximate += d.approximate
        correlation += d.paradigm == "correlation"
    labels: dict[str, int] = {}
    for d in bundle.detections:
        for lbl in (d.source.unsupported if d.source else ()) + d.unknown_labels:
            key = lbl.split(":")[0] + ":" + lbl.split(":")[1] if lbl.count(":") >= 1 else lbl
            labels[key] = labels.get(key, 0) + 1
    return {
        "detections": len(bundle.detections),
        "by_frontend": by_frontend,
        "exact": len(bundle.detections) - approximate,
        "approximate": approximate,
        "correlation": correlation,
        "candidates": len(bundle.candidates),
        "checks": len(bundle.checks),
        "errors": len(bundle.errors),
        "warnings": len(bundle.issues) - len(bundle.errors),
        "unsupported_labels": dict(sorted(labels.items(), key=lambda kv: -kv[1])),
    }
