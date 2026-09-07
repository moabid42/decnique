# decnique

> New here (human or AI)? Start with `[AGENTS.md](AGENTS.md)` — a two-minute explanation,
> the layout, the invariants, and the traps.

A domain-specific language for writing **detections** (a security team's alarm rules)
and **candidates** (an attacker's technique) against **one shared event model**, so the
two can be compared directly.

This repository is the *language* only — grammar, parser, AST, formatter, the
three-valued interpreter, the event/predicate/trace model, and the four SIEM
front-ends that translate real rules into the DSL, plus the coverage/stealth/chains
engine (`decnique/smt/`, `decnique/graph/`) and an interactive shell.

The coverage engine (`decnique/smt/`) answers `Reach ∧ Log ∧ ¬⋁Observes` over a finite
**atom abstraction** of string fields — no z3 string theory; see
`docs/COVERAGE_ABSTRACTION.md` for the idea, the measurements, and what was changed.

image

## Layout

```
decnique/
  dsl/            grammar.lark, parser, AST, formatter, interpreter, loader, yaml_io
  model/          event_fields (the closed vocabulary), predicates, trace (TraceSpec)
  frontends/      secops (YARA-L), sigma, elastic, panther  -> DSL
  catalogs/       udm field-map used by the SecOps front-end
  detections.py   DetectionLibrary: observing() and admitting() on concrete events
  cli.py          command-line entry point
```



## The four top-level constructs

- **detection** — a pattern in the logs that should raise an alarm (single- or
multi-event, with joins, windows, ordering, aggregates, and count conditions).
- **candidate** — the mirror image: what an attacker *needs* (`required`) and the
trace they *leave* (`footprint`, with `repeat`/`within`/`distinct`).
- **check** — a saved question (e.g. a boundary assertion).
- **ruleset** — a bundle of includes with enable/disable toggles.

Both a detection and a candidate bottom out in the same event form, which is what
makes them comparable.

## Install & use

```bash
uv venv && source .venv/bin/activate   # or python -m venv .venv
uv pip install -e .           # or '.[dev]' — quoted — for the tests, the linter and the hooks
pytest                        # ~35 s; -m "not e2e" for the fast loop — see CONTRIBUTING.md
```

```python
from decnique import parse_text, format_bundle, DetectionLibrary, event_from_audit_log

bundle = parse_text(open("rules.decn").read(), "rules.decn")
print(format_bundle(bundle))                       # canonical text; parse(format(x)) == x

lib = DetectionLibrary(bundle)
ev  = event_from_audit_log(one_cloud_audit_log_json)
obs = lib.observing(ev)      # Observes(R, e): which rules fire, which are "unknown"
```



## In the shell

Every command reads `<object> <verb> [args…]`.  Objects hold state; `ask` runs the math.

```
rules load <rules/> examples/candidates/candidates.decn     # detections (+ candidates / checks in the same files)
rules list ~                                     # only the approximate rules
rules inspect <id>   ·   rules dsl <id>          # one rule with context / just its DSL
candidates inspect <id>   ·   checks load examples/checks/checks.decn
account load examples/accounts/custom/account.json               # or a raw gcloud export
ask blindspots resourcemanager.projects.setIamPolicy
ask stealth escalate_project_iam   ·   ask chains   ·   ask check
reports list   ·   reports show <file>   ·   reports diff <a> <b>
help <object> [verb]
```

## The honesty mechanism

Anything the language cannot express becomes a first-class `unknown("label")` atom;
the rule is flagged `approximate` and the interpreter answers three-valued —
**yes / no / don't know** — never forcing a false yes or no.

## Roadmap / future work

`CHANGELOG.md` records what has already landed. This is what is next, grouped by theme.

**Coverage as a measure** — turn the binary covered / not-covered verdict into a quantity.

- [ ] **Holes as regions, not single witnesses.**  
Return the whole evading set over a technique's free variables
(e.g. `window ∈ [600,899] ∧ method=PATCH`), not just one example event.
- [ ] **Cost-weighted coverage measure.**  
Measure the safe region (volume for numeric axes, integer-point count for discrete ones),
weighted by attacker cost, reported as a number with an uncertainty band. This *is* the
severity ranking of gaps — the smallest, cheapest-to-reach holes rank first.
- [ ] **Escape distances / brittleness.**  
For an action a rule *does* catch, how small a change on each axis slips it out of every rule —
surfacing rules that catch something only by a hair.

**Shrink the translation residue** — every `unknown` is a real detection the tool steps around.

- [ ] **Function-derived, relational, and aggregate rules.**  
After the parser fixes, ~42 of 922 SecOps corpus rules are still approximate (2 of 27 once
filtered to GCP). What remains: values computed from a field (`re.capture`, `re.replace`,
`strings.concat`, `base64_decode`), field-vs-field comparisons (`$e.a = $e.b`), and
group aggregates (`count_distinct`). Add model support (keep the real value only for the
fields that need it) to close them, keeping the `unknown` honesty for what still cannot fit.
- [ ] **Reference lists as data.**  
Let the user load `%list` contents (watchlists, allow-lists) via config, so `field in %list`
becomes an exact membership test instead of `unknown`.
- [ ] **Evaluate IAM Conditions.**  
A conditional binding is currently kept *unconditionally*, so reachability is
over-approximated (it may report a gap a time/tag/IP condition would actually block). Parse
and evaluate the condition so `Reach` is exact.
- [x] **A richer technique library.**  
Wired-together GCP techniques for `ask chains` / `ask stealth`, plus replayable event traces
(`examples/candidates/candidates_medium.decn`, `examples/candidates/candidates_advanced.decn`,
`examples/events/events.json`).

**Grounding & scale**

- [ ] **Loop back to real logs.**  
Ingest actual audit-log samples to check the tool's own assumptions, and confirm an exported
"gap" event truly stays silent in a real SIEM — turning *we believe this is a gap* into
*we watched it go uncaught*.
- [ ] **Faster whole-account audits.**  
Cache each method's solver domain across permissions that share methods, so an owner-level
`ask blindspots` scan drops well under its current ~10–20 min.

**Stretch (beyond the thesis)**

- [ ] **A second cloud.**  
Everything is GCP IAM today; a new catalog + account importer + front-end idioms would open
the same questions for AWS or Azure.
