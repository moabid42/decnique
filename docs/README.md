# decnique wiki

This wiki explains decnique from three viewpoints: the security engineer using it, the detection
author describing rules and attacker techniques, and the contributor changing its internals.

decnique answers a deceptively hard question: **given the permissions in one GCP account, its
audit-log configuration, and a concrete detection corpus, what can an attacker do without being
observed?** It translates several native rule formats into one DSL, reasons symbolically over that
shared model, and replays every proposed witness through a concrete evaluator before reporting it.

## Choose a path

- New user: [Getting started](getting-started.md) → [Command reference](command-reference.md)
- Detection author: [DSL reference](dsl-reference.md) → [Analysis guide](analysis-guide.md)
- Platform engineer: [Inputs and integrations](inputs-and-integrations.md) →
  [Architecture](architecture.md)
- Contributor: [Architecture](architecture.md) → [Development guide](development.md)
- Anyone interpreting a result: [Concepts and verdicts](concepts-and-verdicts.md) →
  [Troubleshooting](troubleshooting.md)
- Looking for worked tasks: [Cookbook](cookbook.md)

## What is implemented

| Capability | What decnique does |
|---|---|
| Rule ingestion | Loads native Google SecOps/YARA-L, Elastic, Sigma, Panther, and `.decn` rules |
| Account ingestion | Loads decnique JSON, raw `gcloud` IAM exports, Cloud Asset Inventory results, Terraform state/plan JSON, and native `*.tf.json` |
| Event evaluation | Evaluates one event, a complete ordered trace, correlation windows, joins, order, counts, and supported aggregates |
| Blind-spot analysis | Finds a reachable, logged event for a permission that no loaded rule observes, or proves coverage over the encoded domain |
| Technique analysis | Determines whether a concrete candidate footprint can evade every rule |
| Chain analysis | Finds shortest privilege-escalation paths made only of stealthy techniques and replays the whole path against correlation rules |
| Saved checks | Runs coverage, candidate, comparison, dead-rule, redundancy, boundary, step, attempt, and public-access assertions |
| Evidence workflow | Saves Markdown/JSON/YAML reports, compares runs, exports witnesses as Cloud Audit Log JSON, and suggests starter DSL detections |
| Catalog browsing | Explores GCP permissions, audit methods, roles, logging state, rule mentions, attack tags, and account holders |
| Automation | Supports one-shot commands, scripts, JSON output, stable exit codes, and a lower-level compatibility CLI |

## The mental model in one minute

A rule is a `detection`. An attacker action is a `candidate`: it states the permissions required,
the events it leaves, and optionally the permissions it gains. An `Account` supplies two facts:
who can perform an action (`Reach`) and whether the action is written to the audit log (`Log`).

For a permission, blind-spot analysis asks:

```text
exists event: Reach(event) and Log(event) and not ObservedByAnyRule(event)
```

For a candidate, stealth analysis asks the analogous question over an entire event schedule.
Chain analysis composes stealthy candidates by treating each candidate's `gains` as the next
state's permissions.

There are three answers, never two:

- a concrete finding, with a replayed witness;
- a proof that no witness exists within the exact model; or
- an inconclusive/unknown result where translation or bounded refinement prevents either claim.

Read [Concepts and verdicts](concepts-and-verdicts.md) before interpreting production results.

## Repository map

```text
decnique/
  dsl/          language grammar, parser, AST, formatter, loader, concrete predicates
  model/        event fields, predicate trees, trace/correlation structures
  frontends/    native rule translators
  env/          account Reach/Log model and GCP/Terraform importers
  catalogs/     method, permission, role, tag, and UDM mapping data
  eval/         authoritative concrete trace evaluator
  smt/          symbolic event/trace encoders and coverage/stealth engines
  graph/        privilege-state transitions and chain search
  ui/           shell, commands, rendering, settings, reports, catalog browser
  checks.py     saved-check engines
  answers.py    JSON-serializable engine reports
examples/       account, candidate, check, event, and Terraform examples
tests/          unit, property, integration, corpus, and process-level tests
run.py          interactive and batch launcher
```

## Wiki pages

- [Getting started](getting-started.md) — install, first analysis, interactive and CI workflows
- [Concepts and verdicts](concepts-and-verdicts.md) — Reach, Log, Observes, exactness, replay, and result interpretation
- [Command reference](command-reference.md) — every shell object, verb, setting, flag, and exit code
- [DSL reference](dsl-reference.md) — write detections, candidates, checks, and rulesets
- [Analysis guide](analysis-guide.md) — what each engine asks, how it works, and how to use its evidence
- [Inputs and integrations](inputs-and-integrations.md) — rule formats, accounts, events, catalogs, Terraform, and exports
- [Architecture](architecture.md) — data flow, modules, symbolic abstraction, frontends, and trust boundaries
- [Cookbook](cookbook.md) — practical audits, techniques, CI checks, migrations, and replay workflows
- [Development guide](development.md) — setup, tests, extension recipes, conventions, and safety invariants
- [Troubleshooting](troubleshooting.md) — common surprises, approximate results, and input problems
