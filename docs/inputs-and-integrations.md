# Inputs and integrations

decnique combines four kinds of input: detection rules, account state, event traces, and bundled
GCP catalog data. This page describes what each importer preserves and where approximation enters.

## Rule loading and discovery

`rules load` accepts individual files and recursively scans directories. Files are recognized by
suffix and content:

| Kind | Recognition |
|---|---|
| DSL | `.decn` |
| Google SecOps/YARA-L | `.yaral` |
| Elastic | `.toml` containing `[rule]` |
| Sigma | `.yml`/`.yaml` containing `logsource:` and `detection:` |
| Panther | `.yml`/`.yaml` with `AnalysisType: rule`, `correlation_rule`, or `scheduled_rule` |
| Exported AST | `.json` with `detections`, or YAML with `detections` entries tagged as detections |

Directory scans skip common tooling/test/documentation directories, files over 2 MB, and
`_deprecated` unless requested. The default native-rule filter keeps only GCP-relevant content.

Load issues are data, not crashes: broken files produce `LoadIssue` errors or warnings and the
remaining corpus continues loading. Duplicate identical IDs collapse. Conflicting bodies under one
ID keep the first and emit an error.

## Google SecOps/YARA-L frontend

The SecOps parser reads rule blocks and their `meta`, `events`, `match`, `outcome`, `condition`, and
`options` sections. The lowerer supports:

- field/literal comparisons, regexes, case normalization, string contains/prefix/suffix, and CIDR;
- placeholders, including cross-event joins and placeholder-bound distinct counts;
- timestamp comparisons as event ordering;
- match keys, windows, and before/after anchors;
- counts, count-distinct, sum/min/max, constants, and supported aggregate arithmetic;
- Boolean count/aggregate conditions;
- reference-list membership as preserved `InList` nodes;
- `allow_zero_values` and preservation of unknown options.

The versioned GCP Cloud Audit UDM map translates known paths into event-model fields. Unverified
mapping rows are noted. Functions, relational expressions, aggregates, or condition fragments
outside the implemented subset become explicit `unknown`/`CUnknown` nodes. A partially translated
condition retains both understood and unknown parts.

## Sigma frontend

Sigma GCP rules are lowered as single-event detections. Supported selection features include:

- dictionaries, lists of dictionaries, null/missing fields, scalar and list values;
- `contains`, `startswith`, `endswith`, regex, CIDR, numeric range, wildcard, and `all` modifiers;
- Boolean conditions with identifiers, parentheses, `and`/`or`/`not`;
- `1 of X*`, `all of X*`, `1 of them`, and `all of them`.

Known GCP audit fields map to the closed event vocabulary; other fields become raw `udm(...)`
paths. Keyword selections, aggregations, encoding modifiers, and unknown condition forms become
unknown. Sigma uses missing-field semantics, so translated rules enable `allow_zero_values`.

## Elastic frontend

Elastic TOML query rules using KQL support:

- `field:value`, quoted values, wildcards, field existence, and escaped wildcards;
- grouped values such as `field:(A or B)`;
- Boolean `and`/`or`/`not` and parentheses;
- numeric/text range comparisons;
- mapped ECS/GCP fields and raw UDM fallback fields;
- GCP dataset markers that are implied by the loader scope.

KQL string matching is case-insensitive. `event.outcome:success|failure` maps to the Boolean
`granted` field. `new_terms` and `threshold` preserve their base query and add an unknown atom for
the unsupported portion. EQL, ES|QL, machine-learning, Lucene, and unsupported rule types become
unknown rather than broad matches. Deprecated rules require `--deprecated`.

## Panther frontend

A Panther YAML metadata file points to its Python implementation with `Filename`. The current
Python-AST evaluator symbolically executes a practical subset of `rule(event)`:

- conditionals, early returns, loops over known event collections, `continue`, and simple helpers;
- module constants and literal collections;
- `event.get`, `deep_get`, `deep_walk`, `event.udm`, authorization info, and binding deltas;
- equality/membership, Boolean composition, truthiness, and numeric comparisons;
- `startswith`, `endswith`, `lower`, substring tests, `fnmatch`, and regex search/match/fullmatch;
- `any`/`all` and generators over supported literal or event collections;
- selected GCP data-model event-type constants.

Unsupported Python nodes become field-aware `panther:python:*` unknowns. If AST evaluation cannot
recover useful logic, a conservative literal scraper preserves positive method/permission tests
and conjoins unknown Python logic. Negated method tests are never inverted into an incorrect
positive set. Threshold metadata becomes a count and dedup window; Panther correlation-rule
metadata outside the trace model remains unknown.

## Native AST documents

The lower-level import command can write a complete bundle as YAML or JSON:

```bash
decnique-tooling import native-rules/ -o translated --yaml --json
```

These documents serialize every predicate, trace, aggregate, check, candidate, ruleset, source,
unknown label, and load issue as plain data. Loading selects YAML/JSON from the suffix. Older
predicate documents without the newer `node` discriminator are supported where tests pin
compatibility. Unknown node kinds are rejected rather than guessed.

## Account schema version 1

The native account form is:

```json
{
  "version": 1,
  "name": "production",
  "roles": {
    "roles/customOperator": ["compute.instances.create", "iam.serviceAccounts.actAs"]
  },
  "bindings": {
    "alice@example.com": [
      {"permission": "iam.roles.update", "resource": "projects/prod"},
      {"permissions": ["storage.objects.get"], "resource": "//storage.googleapis.com/projects/_/buckets/data"},
      {"role": "roles/customOperator", "resource": "projects/prod"}
    ]
  },
  "hierarchy": {
    "//storage.googleapis.com/projects/_/buckets/data": "projects/prod",
    "projects/prod": "folders/123"
  },
  "deny": [
    {"principal": "alice@example.com", "permission": "iam.roles.*", "resource": "projects/locked"}
  ],
  "logging": {
    "admin_activity": true,
    "data_access_services": ["storage.googleapis.com"],
    "disabled_methods": ["storage.objects.get"]
  },
  "access_levels": ["trusted"],
  "attack": {
    "principal": "alice@example.com",
    "initial_state": ["compute.instances.create"],
    "goal": "resourcemanager.projects.setIamPolicy",
    "effects": {"technique_id": ["permission.gained"]},
    "max_depth": 5
  }
}
```

### Reach semantics

- `permission` may be exact or a glob such as `storage.*`.
- `resource` is a glob; `*` means any resource.
- A grant on a resource applies to descendants listed in `hierarchy`.
- `resource="*"` in a query means “on some resource”; any appropriately scoped grant can satisfy it.
- A matching deny for the principal, `*`, or `allUsers` overrides the grant.
- A technique is feasible only when one principal holds every required permission.
- Predefined `roles/...` expand from the bundled role catalog. The native `roles` table defines
  custom expansions and takes precedence. An unknown role is retained as a marker grant.

The core `Account` consumes `version`, `name`, roles/bindings, hierarchy, deny, logging, and access
levels. Importer `notes`, explicit `assumptions`, and unknown role expansions become persistent
account assumptions: findings carry caveats and account-dependent proofs remain inconclusive.
The UI separately retains the normalized document and its `attack` plan.

### Log semantics

Admin Activity is on by default. A known Data Access method is logged only when its service or `*`
appears in `data_access_services`. `disabled_methods` overrides either class. Unknown methods are
treated as Admin Activity by the account model, while missing catalog knowledge still causes
approximation in method/permission reasoning.

## Raw gcloud imports

### Project/folder/organization IAM policy

```bash
gcloud projects get-iam-policy PROJECT --format=json > policy.json
```

Load with an explicit scope:

```text
account load policy.json projects/PROJECT
```

Bindings become scoped grants. `auditConfigs` enables Data Read/Write logging per service or
`allServices`. Conditional bindings are kept unconditionally and noted because CEL conditions are
not evaluated. `exemptedMembers` are noted but not modeled.

### Cloud Asset Inventory IAM search

```bash
gcloud asset search-all-iam-policies --scope=projects/PROJECT --format=json > assets.json
```

Each asset policy's resource scopes its grants. Cloud Resource Manager names are normalized;
service-specific full resource names are preserved. A supplied project establishes a hierarchy
edge. If no asset carries `auditConfigs`, Data Access is assumed off and a note explains why.

Member prefixes such as `user:` and `serviceAccount:` are removed to match audit-log principal
emails. `allUsers` and `allAuthenticatedUsers` remain literal. Domain/principal-set style members
cannot be enumerated and remain marker principals with notes. Deleted members are skipped.

## Terraform imports

The preferred input is resolved state or plan output:

```bash
terraform show -json > infra.show.json
```

Native `*.tf.json` also loads, but unresolved `${...}` expressions remain literal and are noted as
approximate. Raw HCL is not parsed.

The importer walks root and child modules in state/plan JSON and handles GCP resources by suffix:

- `google_*_iam_member` and `_iam_binding`: scoped grants;
- `google_*_iam_policy`: JSON policy bindings and audit configs;
- `google_*_iam_audit_config`: Data Access logging;
- `google_*_iam_custom_role`: role expansions;
- `google_project` and `google_folder`: best-effort hierarchy.

It ignores non-Google and data-source shapes. Scope is inferred from project, folder, organization,
bucket, dataset, service account, and other recognized resource attributes; unknown scope becomes
`*` with an approximation note. Terraform describes the account, not detections. A
`google_chronicle_rule` still needs its YARA-L body loaded through `rules load`.

## Event inputs

An event can be a normalized dictionary using the fields in the [DSL reference](dsl-reference.md#event-fields)
or a Cloud Audit Log entry. Raw projection reads:

- method/service from `protoPayload`;
- principal from `authenticationInfo` and derives principal type;
- permissions, grant decision, resource, and resource type from `authorizationInfo`;
- IP and user agent from `requestMetadata`;
- timestamp as epoch seconds from numeric or RFC 3339 input;
- `logName` and any top-level `udm` dictionary.

Event loading de-duplicates identical normalized events while preserving order. Unparseable or
absent timestamps are omitted, which can make timing-dependent rules return unknown.

The reverse export maps known fields back into `protoPayload`; policy-delta UDM labels become
`serviceData.policyDelta.bindingDeltas`. Other UDM fields stay under `udm`.

## Bundled GCP catalogs

`Catalog.gcp()` merges a small hand-checked seed with generated iam-dataset files:

- `gcp_methods.json.gz`: method names, permissions, service, Data Access classification, confidence;
- `gcp_roles.json.gz`: predefined-role permission expansions;
- `gcp_tags.json`: permission attack tags;
- `udm_map.gcp_cloudaudit.v38.json`: SecOps UDM-to-event-field mappings.

Generated method spellings start unverified because one API method can plausibly appear under
several audit-log names. Hand-checked seed entries win. Literal method names found in loaded rules
attest matching generated entries for the current account/session.

Regenerate method/role/tag data with:

```bash
python -m decnique.catalogs.build_gcp /path/to/iam-dataset/gcp
```

The catalog is deliberately honest: an unknown method returns unknown permission information, not
an empty permission set.
