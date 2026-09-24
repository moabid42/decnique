# Analysis guide

This page explains what each analysis computes, the evidence it returns, and the limits of a clean
result. For the vocabulary behind exact and approximate outcomes, first read
[Concepts and verdicts](concepts-and-verdicts.md).

## Blindspots: audit the whole permission surface

```text
ask blindspots [permission...]
```

For each permission, the engine builds a domain from:

- principals that can reach the permission;
- resources inside their grant scope;
- catalog methods that exercise the permission and are logged in this account;
- fixed method facts such as service, product name, event type, and required fields;
- `granted = true` for a successful action.

It then searches for an event outside the union of rules that can fire on one event. Correlation
and other non-single-event rules are not used to prove single-event coverage, but every proposed
witness is replayed against the entire non-vacuous library before acceptance.

### Read the result

- **BLIND SPOT**: a concrete reachable, logged event was replayed and no rule definitely fired.
- **covered**: the exact symbolic domain is unsatisfiable; the listed rules are an UNSAT core that
  jointly covers it.
- **inconclusive/exhausted**: refinement could not establish either result soundly.
- **unreachable**: no principal has the permission in the requested scope.
- **no logged method**: the account cannot emit a catalogued logged use of the permission.

The witness is intentionally simple. Optional fields and atomic tests are minimized for small
libraries, so the output tends to show the smallest distinction from existing rules.

### Watched and unwatched changes

The UI probes the atoms used by rules and groups satisfiable variants into change classes. A
watched row names rules that catch it. An unwatched row gives a witness and, when possible, the
nearest rule conditions it dodges. These rows explain *why* a permission contains a gap; they are
not a percentage coverage metric.

Explanation modes:

```text
config blindspots.explain rules
config blindspots.explain formula
config blindspots.explain both
config blindspots.explain words
config blindspots.raw on
```

`words` is a hard-coded IAM binding-delta vocabulary. For other fields it falls back to rule
syntax. `formula` describes the blind region using the rules' own atomic tests.

### Typical blind-spot workflow

```text
catalog methods resourcemanager.projects.setIamPolicy
account who resourcemanager.projects.setIamPolicy
rules admits SetIamPolicy
ask blindspots resourcemanager.projects.setIamPolicy
ask suggest resourcemanager.projects.setIamPolicy
```

Inspect method verification and Data Access logging before treating a finding as a rule defect.

## Stealth: test one concrete technique

```text
ask stealth [candidate-id]
```

The engine first finds a principal holding every `required` permission. It expands each footprint
step into `repeat` occurrences, applies method, `where`, `within`, `distinct`, order, span, catalog
realism, authorization, and shared-field constraints, then encodes evasion of the tractable rate-
rule subset. The concrete oracle validates the candidate footprint and every rule over the visible
schedule.

Current symbolic rate rules have one event variable, no joins/grouping/aggregates/order, a count
condition, and at most an unanchored window. Other rules still participate in replay but cannot
support an `always_detected` proof.

### Outcomes

- `evasive`: a schedule realizes the footprint and no rule fires.
- `always_detected`: exact evasion constraints are UNSAT. `caught_by` names the rate rules in the
  core when available.
- `not_feasible`: no single principal holds all required permissions.
- `exhausted`: bounded refinement or an uncertain footprint prevented a sound answer.

If a footprint method is not logged, its occurrences are hidden from detection replay and listed
under `unlogged`. That is an audit-configuration gap, not a weakness in the rules.

`actor` and candidate-level `context` constrain every occurrence. `required ... on` constrains
steps tied to that permission by the catalog. Both symbolic search and concrete replay enforce
resource grants and denies. A contradictory candidate is `not_feasible`, rather than a vacuous
detection proof; unresolved candidate constraints remain inconclusive.

## Chains: search privilege transitions

```text
ask chains <goal-permission> [--from principal] [--start p1,p2,...]
```

Each candidate with non-empty `gains` becomes a graph edge:

```text
state contains every required permission
    -- run candidate stealthily -->
state union candidate.gains
```

The search is breadth-first, so the first returned route has the fewest technique hops. At each
state, the account is rebuilt so the selected principal has exactly the state's permissions; the
rest of the account, catalog, hierarchy, denies, and logging configuration are inherited.

Every hop must return `evasive`. The accumulated trace is then replayed back-to-back and, when
rules have windows, once more after a delay longer than the largest window. A correlation rule
across previous hops can therefore reject a path even when each hop is stealthy alone.

### Inputs and interpretation

The account can carry defaults:

```json
{
  "attack": {
    "principal": "attacker@example.com",
    "initial_state": ["iam.serviceAccountKeys.create"],
    "goal": "resourcemanager.projects.setIamPolicy",
    "effects": {"candidate_id": ["permission.gained"]},
    "max_depth": 4
  }
}
```

Candidate `gains` are used unless `effects` overrides that candidate. Command flags override the
principal/start/goal plan assembled by the UI.

A found path is replay-backed. A no-path result is inconclusive when its reason is `depth_bound`
(unexplored states), `unknown_edge` (an undecided technique), or `schedule_bound` (the selected
schedules failed cross-hop replay, but alternatives remain untested). These results set
`inconclusive: true` and exit 4 with `--fail-on unknown`. Reason `exhausted` means the modeled
permission graph was exhausted without an undecided transition or rejected schedule. It is not a
claim about techniques outside the loaded library or undeclared privilege effects.

## Checks: executable policy assertions

```text
ask check [id...]
```

Checks phrase engine questions as version-controlled DSL and invert them into defender-oriented
`pass`, `fail`, or `unknown`.

### `coverage`

Runs blind-spot search over `permission`, `permissions like`, `scope`, or all reachable catalog
permissions. `event` narrows the event class, and `rules [...]` restricts the rule library.

- Pass: every probed event is covered, or the question is vacuous because it is unreachable/unlogged.
- Fail: at least one replayed unobserved event exists.
- Unknown: nothing matched, refinement exhausted, or a proof leaned on approximate rules.

### `candidate`

Runs stealth analysis for `for <candidate>` against optional selected rules. Always detected and
infeasible are passes; evasive is a fail; exhausted is unknown.

### `compare`

Checks both set differences between `left` and `right` single-event rules. Pass means both
directions are UNSAT. A distinguishing atomic model produces fail. Correlation rules return
unknown, as does an apparent equivalence involving approximate encodings.

### `dead_rules`

For each selected single-event rule, searches for a reachable, logged event on which it fires.
Fail means exact UNSAT: the rule is dead in this account. An approximate dead rule is unknown.

### `redundant_rules`

For each selected rule, searches for a reachable, logged event it observes alone. Fail means every
event it observes also trips another rule. A replayed unique event proves the rule contributes
independent coverage.

### `boundary`

Asks whether any reachable, logged event matching `event`, except one matching `allowed`, can slip
past the chosen observation mode. One slip is enough to fail.

- `fires_single`: require a one-event alert.
- `observed`: accept any rule event pattern, including correlation-rule components.
- `fires_bg`: no engine yet; result is unknown.

Remember that referenced `allowed` fields must be present. If absence is also allowed, write
`allowed FIELD matches ... or FIELD missing`.

### `require_coverage` and `attempt_coverage`

Resolve a candidate step's method to its required permissions through the catalog, add its `where`
payload, then run blind-spot search. `require_coverage` fixes `granted = true`; `attempt_coverage`
fixes `granted = false`. Select one step with `step`; omit it to inspect all steps.

### `public_access`

Finds permissions granted to `allUsers` or `allAuthenticatedUsers`, preserves each grant's resource
scope, and asks whether anonymous use can go unseen. Optional permission selectors and
`resource like` narrow the question.

## Suggestions

```text
ask suggest permission.one permission.two
ask suggest permission.one define
```

Suggestions are derived from blind-region/change-class analysis. They provide:

- focused detections for unwatched kinds of change; and
- a method catch-all intended to close the remaining modeled gap.

With `define`, suggested blocks enter only the current session. Always inspect them with
`rules dsl`, rerun the relevant checks, translate/tune them for the target SIEM, and validate an
exported witness in the real platform.

## Reports and regression analysis

Every `ask` verb records a structured in-memory report even when saving is off. With
`config report.save on`, the run also records loaded paths/account, summary, items, and terminal
transcript.

Use JSON for pipelines, Markdown for review, and YAML for editable data. `reports diff` compares
the identity and verdict of findings rather than raw terminal text, making it suitable for showing
what a rule change closed or opened.

`reports export` turns witness event-model dictionaries into Cloud Audit Log-shaped entries. IAM
binding delta fields are placed under `protoPayload.serviceData.policyDelta.bindingDeltas`; other
raw UDM-only fields remain under top-level `udm` because no universal raw-log location is known.
