# DSL reference

The decnique DSL is the shared representation for detections, attacker techniques, saved checks,
and rule bundles. Native SIEM frontends lower into the same AST, so handwritten and translated
rules use the same concrete evaluator and analysis engines.

A `.decn` file may contain any number of four top-level blocks:

```text
detection NAME { ... }
candidate NAME { ... }
check NAME { ... }
ruleset NAME { ... }
```

The canonical formatter guarantees `parse(format(x)) == x`.

## Lexical rules

- `//` begins a comment through the end of the line.
- Names begin with a letter or `_` and continue with letters, digits, or `_`.
- Permissions and similar dotted values are unquoted, for example `iam.roles.update`.
- Strings use double quotes. Supported escapes are `\\`, `\"`, `\n`, and `\t`; other
  backslashes are preserved so regex and escaped glob syntax survive.
- Regex literals may use `/pattern/`; a quoted regex is also accepted after `matches`.
- Durations use an integer and `s`, `m`, `h`, or `d`, such as `30s`, `10m`, or `2h`.
  The grammar recognizes `ms`, but the parser rejects sub-second durations.
- Numbers are non-negative integers. Negative numeric literals are not part of the grammar.
- Keywords are whole tokens, so identifiers such as `events_total` remain valid names.

## Event fields

The closed event model is:

| Field | Type | Source/meaning |
|---|---|---|
| `method` | string | `protoPayload.methodName` |
| `service` | string | service name, often fixed by the method catalog |
| `permission` | repeated string | `authorizationInfo[].permission` |
| `principal` | string, optional | `authenticationInfo.principalEmail` |
| `principal_type` | string, optional | derived `USER` or `SERVICE_ACCOUNT` |
| `resource` | string | normalized authorization resource |
| `resource_type` | string | authorization resource attribute type |
| `project` | string | resource ancestry/project |
| `folder` | repeated string | resource ancestry folders |
| `org` | string | resource ancestry organization |
| `caller_ip` | IP, optional | `requestMetadata.callerIp` |
| `user_agent` | string, optional | caller-supplied user agent |
| `granted` | boolean | authorization decision |
| `time` | time/integer | epoch seconds used by windows and order |
| `event_type` | string | derived UDM event type |
| `product_name` | string | derived UDM product name |
| `log_name` | string | activity/data-access log name |
| `access_levels` | repeated string | request access levels |
| `sent_bytes` | integer | numeric field available to aggregates |
| `received_bytes` | integer | numeric field available to aggregates |

Two field families are open:

- `tags.KEY` reads `event["tags"]["KEY"]`.
- `udm("path")` reads `event["udm"]["path"]` and is stored internally as `udm:path`.

In a multi-event detection, qualify fields with the event variable: `login.principal` or
`grant.udm("target.resource.attribute.labels[x]")`. Unqualified known fields are allowed and are
interpreted in the current event predicate, but explicit qualification is clearer in correlations.

## Predicate expressions

Predicates compose with `not`, `and`, and `or`; precedence is `not`, then `and`, then `or`.
Parentheses override precedence.

### Comparisons

```text
method = "SetIamPolicy"
granted != false
sent_bytes >= 1000
principal = "ADMIN@EXAMPLE.COM" nocase
```

Operators are `=`, `!=`, `<`, `<=`, `>`, and `>=`. `nocase` applies case-insensitive string
matching. Ordered comparisons are meaningful for numeric/time values and supported concrete values.

### String tests

```text
resource startswith "projects/"
principal endswith ".gserviceaccount.com" nocase
user_agent contains "curl"
method like "*.SetIamPolicy"
principal matches /.*@example\.com$/ nocase
```

`like` uses SIEM glob semantics:

- `*` matches any sequence;
- `?` matches one character;
- `\*` and `\?` match literal wildcard characters;
- character classes such as `[abc]` are not supported and are treated literally.

`matches` uses a Python/RE2-style regular expression with a partial, unanchored search unless the
pattern contains anchors.

### Membership and networks

```text
method in ["CreateRole", "UpdateRole"]
caller_ip in cidr ["10.0.0.0/8", "192.0.2.0/24"]
principal in %trusted_admins nocase
principal in regex %admin_patterns
caller_ip in cidr %trusted_networks
```

Literal list membership is exact. `%name` denotes an external SecOps-style reference list. The
public shell does not currently load reference-list contents, so such a predicate normally
evaluates don't-know. Library callers can supply `ref_lists` to `DetectionLibrary`.

### Presence

```text
principal exists
caller_ip missing
```

`missing` is syntax sugar for `not <field> exists`. Optional fields have explicit presence bits in
the symbolic model. When a check constrains an event with a predicate, referenced fields are also
required to be present.

### Repeated fields

`permission`, `folder`, and `access_levels` are repeated. Prefix a leaf test with `any` or `all`:

```text
any permission startswith "iam."
all access_levels in ["corp", "trusted"]
```

No quantifier means `any` for a repeated field. On a scalar field it is simply the scalar test.

### Constants and unknowns

```text
true
false
unknown("panther:unsupported_helper")
```

Use `unknown(...)` when a condition exists but cannot be represented honestly. It is a first-class
three-valued atom, not a wildcard. Frontends use labels such as `secops:function:...` to preserve
translation residue. Handwritten rules should prefer a truthful unknown over deleting logic.

## Detections

### Single-event detection

```text
detection owner_binding_added {
  meta {
    severity = "high"
    enabled = true
  }
  event method = "SetIamPolicy"
    and udm("target.resource.attribute.labels[ser_binding_deltas_action]") = "ADD"
    and udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
}
```

`event EXPR` is sugar for one variable named `e` with condition `#e >= 1`. Metadata values may be
strings, integers, booleans, or duration tokens and do not change evaluation semantics.

### Multi-event detection

```text
detection key_then_token_burst {
  events {
    key: method = "google.iam.admin.v1.CreateServiceAccountKey"
    tok: method = "iam.serviceAccounts.getAccessToken"
  }
  join { key.principal = tok.principal }
  group by tok.principal
  window 30m
  order key < tok
  condition #key >= 1 and #tok >= 3
}
```

Each event variable has its own predicate. If `condition` is omitted, every event variable must
occur at least once.

### Joins

```text
join {
  create.principal = use.principal
  create.resource = use.resource
}
```

Join sides must be qualified fields from different event variables. Multiple joins are conjunctive.
The concrete evaluator groups events by connected join/group dimensions before applying conditions.

### Grouping

```text
group by event.principal, event.project
```

Grouping partitions matched events. Conditions and aggregates are evaluated per group; a rule fires
if at least one group satisfies the complete trace specification.

### Windows

```text
window 15m
window 10m before change
window 1h after login
```

An unanchored window bounds the group's overall time span. An anchored window limits events to the
named event variable's before/after interval. Missing or unusable timestamps produce uncertainty
where a timing decision cannot be made.

### Order

```text
order create < use < delete
```

Names must be declared event variables and cannot repeat. Consecutive ordering constraints require
an earlier matching event before a later one.

### Aggregates

```text
aggregates {
  bytes = sum(download.sent_bytes)
  actors = count_distinct(download.principal)
  events_total = count(download.method)
  peak = max(download.received_bytes)
  weighted = bytes * 2
  suspicious = if(download.user_agent contains "curl", 1, 0)
}
condition bytes > 1000000 or actors >= 5
```

Available functions are `sum`, `max`, `min`, `count`, and `count_distinct`. `count()` may omit its
field; the others require one. Aggregate expressions support `+`, `-`, and multiplication/division
by an integer constant. They may reference earlier names and may use `if(predicate, then, else)`.

Conditions can compare `#event_variable` or an aggregate name to an integer, and compose those
atoms with `not`, `and`, and `or`:

```text
condition (#download >= 5 and bytes > 1000000) or unknown("vendor:condition")
```

### Options

```text
options {
  allow_zero_values = true
  vendor_option = "preserved"
}
```

`allow_zero_values` controls the YARA-L-style zero-value reading. Other options are preserved as
metadata in `RuleOptions.extra` even when the evaluator has no special behavior for them.

## Candidates

A candidate describes feasibility plus an audit footprint:

```text
candidate grant_self_owner {
  meta { tactic = "privilege-escalation" }
  actor principal_type = "USER"
  required {
    resourcemanager.projects.setIamPolicy
  }
  footprint {
    grant: "SetIamPolicy"
      where udm("target.resource.attribute.labels[ser_binding_deltas_action]") = "ADD"
        and udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
        and udm("target.resource.attribute.labels[ser_binding_deltas_member]") startswith "user:"
    span 1h
  }
  context project = "production"
  share principal, project
  gains {
    iam.roles.update
    logging.sinks.delete
  }
}
```

### `actor`

Describes a constraint on the actor using the normal event predicate language. It is parsed,
formatted, inspected, and serialized. The current stealth feasibility engine selects principals
from `required` permissions and does not yet add `actor` as a solver constraint, so do not rely on
it to narrow an `ask stealth` result.

### `required`

Every permission is required and must be held by the same feasible principal. A permission can
carry an `on` predicate:

```text
required {
  storage.objects.get on resource like "projects/prod/*"
}
```

The AST preserves this resource/condition predicate. Current feasibility checks use the permission
set and account grant scope; do not assume `on` is a complete IAM Conditions engine.

### Footprint steps

```text
footprint {
  open: "storage.setIamPermissions"
    where udm("target.resource.attribute.labels[ser_binding_deltas_member]") = "allUsers"
  read: "storage.objects.get" repeat 5 within 20m distinct resource, caller_ip
  order open < read
  span 2h
}
```

Each step has a unique ID and an exact method name. Step options are:

- `repeat N`: require at least N matching occurrences; default 1.
- `within DURATION`: the repeated occurrences must fit one interval of that length.
- `distinct FIELD,...`: count distinct tuples of those field values rather than raw events.
- `where EXPR`: constrain the event payload.
- Footprint `order`: require one step to precede the next.
- Footprint `span`: bound the earliest-to-latest candidate event.

The parser limits a footprint to 16 expanded events by default. This is configurable through the
Python `ParseOptions`, not a shell setting.

### `context`, `share`, and `gains`

`context` records an extra technique constraint. Like `actor`, it currently survives parsing,
formatting, inspection, and serialization but is not yet added to the stealth solver. Put payload
conditions that must affect the current result on the relevant step's `where` clause.

`share` lists fields constrained equal across the symbolic schedule. It defaults to `principal`;
allowed fields are `principal`,
`principal_type`, `caller_ip`, `user_agent`, `project`, `org`, and `folder`.

`gains` supplies graph effects only: after this candidate succeeds, chain state contains those
permissions. It does not change the account permanently and does not affect standalone stealth
analysis. A candidate without gains is valid for `ask stealth` but cannot advance `ask chains`.

## Checks

A check is a named, defender-oriented assertion:

```text
check owner_grant_watched {
  type coverage
  permission resourcemanager.projects.setIamPolicy
  event udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
}
```

Possible option clauses are:

```text
event EXPR
permission dotted.permission
permissions like "glob"
resource like "glob"
allowed EXPR
mode observed
rules [rule_a, rule_b]
for candidate_id
step step_id
left rule_a
right rule_b
scope [permission.one, permission.two]
```

Not every option applies to every type.

### Check types

| Type | Required/useful options | Pass means |
|---|---|---|
| `coverage` | `permission`, `permissions like`, or `scope`; optional `event`, `rules` | every reachable, logged event in scope is observed |
| `candidate` | `for`; optional `rules` | the technique is always detected, or is infeasible vacuously |
| `compare` | `left`, `right` | two single-event rules observe equivalent event sets |
| `dead_rules` | optional `rules` | every selected single-event rule can fire on a reachable, logged event |
| `redundant_rules` | optional `rules` | every selected rule observes some event no other rule observes |
| `boundary` | `event`; optional scope, `allowed`, `mode`, `rules` | no non-allowed matching event slips past the boundary |
| `require_coverage` | `for`; optional `step`, `rules` | every successful realization of the candidate step is watched |
| `attempt_coverage` | `for`; optional `step`, `rules` | every denied (`granted = false`) realization of the step is watched |
| `public_access` | optional permission scope, `resource like`, `rules` | no use by `allUsers` or `allAuthenticatedUsers` goes unseen |

When no permission selector is given, permission-oriented checks inspect reachable catalog
permissions. `rules [...]` restricts the library visible to that check.

Boundary modes are:

- `fires_single` (default): a single event must make a single-event rule fire.
- `observed`: any rule event pattern, including one inside a correlation rule, may observe it.
- `fires_bg`: intended for firing against a background trace; not implemented and always unknown.

Examples for every type live in `examples/checks/checks.decn`.

## Rulesets

Rulesets add includes and enable/disable filters:

```text
ruleset production {
  include "rules/*.decn"
  include "vendor/**/*.yaral"
  disable noisy_rule
  enable required_exception
}
```

Include globs are resolved from the directory of the first loaded DSL detection when available,
otherwise from the current working directory. A pattern matching nothing produces a warning.
`enable` wins over `disable` for the same rule. Naming an unknown rule also produces a warning.

## A complete custom file

```text
detection human_owner_grant {
  event method = "SetIamPolicy"
    and udm("target.resource.attribute.labels[ser_binding_deltas_action]") = "ADD"
    and udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
    and udm("target.resource.attribute.labels[ser_binding_deltas_member]") startswith "user:"
}

candidate become_owner {
  required { resourcemanager.projects.setIamPolicy }
  footprint {
    grant: "SetIamPolicy"
      where udm("target.resource.attribute.labels[ser_binding_deltas_action]") = "ADD"
        and udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
        and udm("target.resource.attribute.labels[ser_binding_deltas_member]") startswith "user:"
    span 10m
  }
  gains { iam.roles.update }
}

check owner_payload_caught {
  type candidate
  for become_owner
}

check all_owner_changes_watched {
  type boundary
  permission resourcemanager.projects.setIamPolicy
  event udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
  allowed udm("target.resource.attribute.labels[ser_binding_deltas_member]") startswith "serviceAccount:"
  mode fires_single
}
```

Validate and canonicalize it:

```bash
python -m decnique.cli parse my-rules.decn
python -m decnique.cli fmt my-rules.decn
python -m decnique.cli fmt --write my-rules.decn
```

Then use it:

```text
rules load my-rules.decn
account load account.json
ask stealth become_owner
ask check owner_payload_caught all_owner_changes_watched
```

## Authoring guidance

- Put the attacker payload in candidate `where` clauses; a method-only candidate asks a broader and
  often less useful question.
- Use real audit-log `methodName` values. `catalog methods <permission>` shows known spellings and
  whether they are verified.
- Keep fields realistic. The catalog pins service/product/event type and required policy-delta
  presence, but arbitrary `udm(...)` fields remain otherwise free.
- If a field may legitimately be absent, encode that explicitly, for example
  `field = "x" or field missing`.
- Scope checks with both permission and event predicates when free fields would otherwise allow an
  odd cross-method witness.
- Preserve unsupported meaning with `unknown("source:reason")`; never replace it with `true` or
  `false` merely to make a rule parse.
- Inspect canonical output with `rules dsl`, `candidates dsl`, or `checks dsl`; round-trip stability
  is part of the language contract.
