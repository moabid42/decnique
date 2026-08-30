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
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

```python
from decnique import parse_text, format_bundle, DetectionLibrary, event_from_audit_log

bundle = parse_text(open("rules.decn").read(), "rules.decn")
print(format_bundle(bundle))                       # canonical text; parse(format(x)) == x

lib = DetectionLibrary(bundle)
ev  = event_from_audit_log(one_cloud_audit_log_json)
obs = lib.observing(ev)      # Observes(R, e): which rules fire, which are "unknown"
```



## The honesty mechanism

Anything the language cannot express becomes a first-class `unknown("label")` atom;
the rule is flagged `approximate` and the interpreter answers three-valued —
**yes / no / don't know** — never forcing a false yes or no.

## Roadmap / future work

Tick a box as each lands. Roughly ordered by how much it widens what the tool can answer.

- [ ] **Real multi-event correlation.**  
Reason about rules that need *several* events   
thresholds (`N in a window`), value aggregates, and joins — instead of stepping around them.
- [x] **A richer technique library.**  
Wired-together GCP techniques for `chains` / `stealth`, plus replayable event traces to test against  
(`examples/candidates_medium.decn`, `examples/candidates_advanced.decn`,  
`examples/events.json`).

- [ ] **Evaluate IAM Conditions.**  
A conditional binding is currently kept *unconditionally*,  
so reachability is over-approximated (it may report a gap a time/tag/IP condition would  
actually block). Parse and evaluate the condition so `Reach` is exact.

- [ ] **Shrink the translation residue.**  
~80 of 230 rules are still not exact (about half of Panther's GCP rules yield no method predicate). Each is a real detection hiding behind `unknown`; add front-end idioms to close the gap.
- [ ] **Loop back to real logs.**  
Ingest actual audit-log samples to check the tool's own assumptions, and confirm an exported "gap" event truly stays silent in a real SIEM —  
turning *we believe this is a gap* into *we watched it go uncaught*.

- [ ] **Faster whole-account audits.**  
Cache each method's solver domain across permissions that share methods, so an owner-level `blindspots` scan drops well under its current  
~10–20 min.
- [ ] **A second cloud.**  
Everything is GCP IAM today; a new catalog + account importer + front-end idioms would open the same questions for AWS or Azure.
- [ ] **Product polish.**  
Severity ranking of gaps, MITRE ATT&CK mapping, and an over-time trend on top of `report diff`.

