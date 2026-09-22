# Cookbook

These workflows combine the commands and DSL into common security-engineering tasks.

## Audit one high-risk permission

```text
rules load ../IAMouflage/data/detections
account load production-policy.json projects/production
catalog methods resourcemanager.projects.setIamPolicy
account who resourcemanager.projects.setIamPolicy
rules admits SetIamPolicy
config blindspots.explain both
config blindspots.raw on
ask blindspots resourcemanager.projects.setIamPolicy
```

Interpret the layers in order:

1. `catalog methods` confirms possible method spellings and logging class.
2. `account who` confirms the permission is actually reachable and at what scope.
3. `rules admits` identifies plausible observers without claiming they fire.
4. `ask blindspots` searches the complete reachable/logged event space represented by rule atoms.
5. The raw witness lets you verify exact fields and replay it later.

If the result is approximate, inspect every unknown rule named by the finding before filing a gap.

## Test an exact attacker payload

Write the payload into a candidate instead of asking only about its permission:

```text
candidate add_self_as_owner {
  required { resourcemanager.projects.setIamPolicy }
  footprint {
    grant: "SetIamPolicy"
      where udm("target.resource.attribute.labels[ser_binding_deltas_action]") = "ADD"
        and udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
        and udm("target.resource.attribute.labels[ser_binding_deltas_member]") = "user:attacker@example.com"
    span 10m
  }
}

ask stealth add_self_as_owner
```

Now compare:

```text
ask blindspots resourcemanager.projects.setIamPolicy
```

It is valid for the exact payload to be always detected while another change using the permission
is a blind spot.

## Model a rate-evasion technique

Suppose a rule fires on five token mints within ten minutes. A candidate can ask whether the same
five actions fit its own one-hour objective while avoiding the rule window:

```text
candidate slow_token_mint {
  required { iam.serviceAccounts.getAccessToken }
  footprint {
    mint: "iam.serviceAccounts.getAccessToken" repeat 5 distinct caller_ip
    span 1h
  }
}
```

`ask stealth slow_token_mint` lets the solver choose times and caller IPs, then replays the schedule
through the concrete rate rule. Add `within 10m` to the step if the attack itself requires the burst.

## Detect a multi-stage sequence

```text
detection key_then_token {
  events {
    key: method = "google.iam.admin.v1.CreateServiceAccountKey"
    tok: method = "iam.serviceAccounts.getAccessToken"
  }
  join { key.principal = tok.principal }
  window 1h
  order key < tok
  condition #key >= 1 and #tok >= 3
}
```

Validate against a real trace:

```text
events load examples/events/events.json
events trace all
rules inspect key_then_token
```

Then create a candidate with matching steps and use `ask stealth`. Correlation rules participate in
concrete replay even when they are outside the exact stealth encoding.

## Build a regression check suite

Create `security-policy.decn`:

```text
check service_account_keys_covered {
  type coverage
  permission iam.serviceAccountKeys.create
}

check owner_escalation_caught {
  type candidate
  for add_self_as_owner
}

check owner_boundary {
  type boundary
  permission resourcemanager.projects.setIamPolicy
  event udm("target.resource.attribute.labels[ser_binding_deltas_role]") = "roles/owner"
  allowed udm("target.resource.attribute.labels[ser_binding_deltas_member]") startswith "serviceAccount:"
    or udm("target.resource.attribute.labels[ser_binding_deltas_member]") missing
  mode fires_single
}

check no_dead_rules { type dead_rules }
check no_redundant_rules { type redundant_rules }
```

Run it in CI:

```bash
python run.py \
  --rules native-rules/ candidates.decn security-policy.decn \
  --account account.json \
  --json \
  --report reports \
  --format json \
  --fail-on unknown \
  ask check
```

This fails with 2 on a failed check, 4 on an unknown check, and 3 on input errors.

## Find publicly reachable, invisible actions

```text
catalog perms --reachable
account who allUsers
account who allAuthenticatedUsers
```

Define and run:

```text
check public_project_use {
  type public_access
  resource like "projects/production*"
}

ask check public_project_use
```

Add a permission selector if the account exposes many unrelated services. The check evaluates each
anonymous grant on its own resource scope.

## Compare two rules during migration

```text
check old_equals_new {
  type compare
  left old_rule
  right new_rule
}

ask check old_equals_new
```

A failure gives the direction of the difference (`old_rule only` or `new_rule only`) and a compact
atom assignment. Compare works on single-event rules. An approximate translation makes apparent
equivalence unknown, which is the safe outcome for a migration gate.

## Find dead and redundant content

```text
check selected_rules_live {
  type dead_rules
  rules [rule_a, rule_b, rule_c]
}

check selected_rules_distinct {
  type redundant_rules
  rules [rule_a, rule_b, rule_c]
}

ask check selected_rules_live selected_rules_distinct
```

These checks are account-relative. A rule can be valuable globally but dead in an account that
cannot emit its event, and redundant within one selected corpus but unique in another.

## Search for a stealthy escalation path

Load a connected candidate library:

```text
candidates load examples/candidates/candidates_advanced.decn
account load examples/accounts/custom/account.json
candidates list
ask chains resourcemanager.projects.setIamPolicy
```

To test a hypothetical foothold:

```text
ask chains resourcemanager.projects.setIamPolicy \
  --from attacker@demo.iam.gserviceaccount.com \
  --start iam.serviceAccountKeys.create
```

The shell command itself must be entered on one line; it is wrapped here only for readability.
Only candidates with `gains` form edges. Inspect each hop's schedule, gains, delay, unknown rules,
and approximation tag.

## Close a finding and prove the regression

```text
config report.save on
config report.dir reports
config report.format md
ask blindspots iam.serviceAccountKeys.create
```

Generate a starting point:

```text
ask suggest iam.serviceAccountKeys.create define
rules list
ask blindspots iam.serviceAccountKeys.create
reports list
reports diff reports/before.md reports/after.md
```

Use `rules dsl <suggested-id>` to extract the suggested rule. Replace it with the operational rule
in the native SIEM, reload that native file, and rerun. This tests the translator and the actual
rule semantics instead of only the generated DSL.

## Replay a finding outside decnique

Immediately after a finding-producing run, in the same session:

```text
reports export /tmp/decnique-witnesses.json
```

Use the optional final `1` argument to export only the first finding. `reports show` re-renders a
saved report but does not make it the in-memory export source; export currently operates only on the
last `ask` run.

The output is a list even for one finding. `_decnique` metadata is extra provenance; remove it if
the destination ingestion endpoint rejects unknown top-level fields. Validate that the destination
parser produces the UDM fields your rule reads before concluding the rule is silent.

## Audit translation residue

```text
rules summary
rules list ~
rules inspect approximate_rule_id
rules dsl approximate_rule_id
```

Prioritize unsupported labels that occur in GCP rules relevant to reachable permissions. A large
number of approximate rules elsewhere in a multi-platform corpus does not automatically weaken a
particular result.

## Use the Python API

```python
from decnique import DetectionLibrary, event_from_audit_log, format_bundle, parse_text
from decnique.answers import full_report
from decnique.env import load_account

bundle = parse_text(open("custom.decn", encoding="utf-8").read(), "custom.decn")
print(format_bundle(bundle))

lib = DetectionLibrary.load("native-rules", "custom.decn")
account = load_account("account.json")

event = event_from_audit_log(raw_cloud_audit_log)
print(lib.observing(event))
print(full_report(lib, account, permissions=("iam.serviceAccountKeys.create",)))
```

For reference-list-backed rules, construct `DetectionLibrary(bundle, ref_lists={...})`. Engine
report functions return ordinary JSON-serializable dictionaries.
