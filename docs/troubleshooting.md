# Troubleshooting

## `rules load` found nothing

Check these in order:

1. The path exists and the file type/content is recognized.
2. The default GCP filter did not remove a non-GCP or insufficiently labelled rule.
3. The rule is not under `_deprecated/`.
4. The file is below the 2 MB loader limit.
5. For Panther, the YAML has a supported `AnalysisType` and its `Filename` sibling exists.

Try `rules load --all --deprecated <path>` and then `rules summary`. A successful scan that adds
zero requested objects prints a note. Parse failures appear as load errors rather than terminating
the session.

## A rule is marked `~` approximate

Run:

```text
rules inspect RULE_ID
```

The untranslated table identifies the frontend, label, and often raw construct/field. Approximate
does not mean useless: an understood branch can still definitely include or exclude an event. It
means a conclusion that depends on the residue must remain unknown or be tagged approximate.

Common causes are SecOps functions/reference lists, unsupported Elastic rule types, Sigma
aggregations/encoding modifiers, and Python operations outside the Panther AST subset.

## `ask blindspots` reports an unexpected simple event

The witness minimizer prefers absent optional fields and false atoms, so the smallest gap may be a
boring change such as a role removal. Use:

```text
config blindspots.explain both
config blindspots.raw on
ask blindspots PERMISSION
```

Read the watched/unwatched change rows instead of assuming the example is the only gap. To ask
about a meaningful payload, write a candidate or a `coverage`/`boundary` check with an `event`
constraint.

## The witness has an odd field for its method

Only catalog invariants tie fields to methods. Most raw `udm(...)` and tag fields are otherwise
free because inventing undocumented relationships would be unsound. A check narrowed only by a
rule subset can therefore produce a strange but model-valid combination.

Scope the question with a `permission` and relevant `event` predicate, or add a verified catalog
invariant when the relationship is universally true in real logs.

For policy-change methods, generated witnesses require the IAM binding-delta fields to be present.
Concrete event replay can still evaluate a real exported log where those fields are absent.

## Blindspots says gap while stealth says always detected

This is expected when the permission has multiple methods or payloads. Blindspots asks whether
*any* reachable/logged use of the permission escapes. Stealth asks whether the candidate's exact
footprint and `where` payload escape.

Compare the blindspot witness with `candidates inspect ID`. Add missing payload constraints to the
candidate if it does not yet describe the intended attack.

## A permission is `unreachable`

Use:

```text
account who PERMISSION
account show
```

Check role expansion, resource scopes, hierarchy edges, wildcard permission spelling, and denies.
For a raw gcloud IAM policy, reload it with the correct explicit resource. Conditional grants are
kept unconditionally, so conditions cannot be the reason for an unreachable result.

## A permission has `no_logged_method`

Run `catalog methods PERMISSION`. Possible causes:

- the catalog has no method for the permission;
- every known method is Data Access and the service is not enabled;
- every method is in `disabled_methods`;
- the imported asset search contained no audit configuration.

This is not rule coverage. Fix logging/catalog input or treat it as a telemetry gap.

## A gap is approximate because of an unverified method

Generated iam-dataset entries can contain plausible method spellings that have not been confirmed
in audit logs. If any verified spelling exists, the engine prefers only verified names. When none
exists, a witness may use an unverified name and receives a caveat.

Load a real rule that literally names the method to attest it for the session, or add a hand-checked
seed fact with evidence. Do not mark it verified merely to remove a warning.

## `ask stealth` says `not_feasible`

All required permissions must be held by the same principal. `account who` on each permission may
show different holders, which is still infeasible.

Candidate `actor`, `context`, and required-`on` predicates are not current feasibility constraints.
The missing-permission list is based on the `required` permission strings and account Reach.

## `ask stealth` or blindspots says `exhausted`

Exhaustion is deliberately not treated as coverage. The engine reached its refinement bound or had
to block an unrealizable/unknown model without a proof-grade consistency clause.

Reduce the question to fewer rules/fields, inspect approximate rules, simplify candidate unknowns,
or reproduce it through the Python API with diagnostic instrumentation. Raising a refinement bound
is an API-level change; there is no shell setting for it.

## A candidate ignores `actor` or `context`

Those fields are implemented in the language, formatter, serializer, and inspector, but not yet
added to `stealth_feasible` constraints. Put conditions that must affect analysis into each
relevant footprint step's `where`. Likewise, `required PERMISSION on EXPR` is preserved but current
feasibility is permission-based.

## A candidate footprint does not match loaded events

Check:

- exact method spelling;
- enough occurrences for `repeat`;
- distinct tuples rather than merely distinct events;
- usable timestamps for `within`, order, and span;
- `where` fields nested under `udm` or `tags` correctly;
- duplicated Cloud Logging exports with the same `logName`, `timestamp`, and `insertId`, which
  `events load` removes; otherwise equal occurrences are deliberately preserved for count and rate
  detections.

Use `events list`, `events inspect N`, and `candidates inspect ID` side by side.

## A correlation rule is unknown

Missing timestamps, joins on missing values, uncertain event predicates, unsupported aggregate
values, or `CUnknown` conditions can all produce don't-know. `events trace all` shows the verdict;
`rules inspect` shows translation residue. Ensure raw timestamps parse as RFC 3339 or numeric epoch
seconds.

## A glob behaves differently than expected

The DSL uses SIEM glob syntax: `*` and `?` are wildcards; escaped versions are literals; bracket
classes are not supported. Use `matches /.../` for regular expressions. Remember shell quoting:

```text
catalog perms "*.setIamPolicy"
```

Unquoted `*` can be expanded by an outer shell in batch mode before decnique sees it.

## An `allowed` boundary exception does not apply

Event constraints require their referenced fields to be present. If missing fields should also be
allowed, say so:

```text
allowed principal startswith "serviceAccount:" or principal missing
```

Also confirm the boundary mode. `observed` accepts correlation event patterns; `fires_single`
requires a one-event alert. `fires_bg` is intentionally unknown because it has no engine.

## A chain finds no path

Check that:

- candidates are loaded and have non-empty `gains`;
- gains connect to another candidate's exact required permission strings;
- the initial state contains the first technique's requirements;
- the chosen principal and goal are correct;
- each hop is individually evasive;
- no cross-hop correlation fires for both attempted delay strategies;
- an account `attack.effects` override is not replacing DSL gains unexpectedly;
- `max_depth` did not produce `depth_bound`.

Remember that no-path `exhausted` is over the schedules selected for edges, not all possible
schedules.

## Reports are not appearing

Check:

```text
config report.save
config report.dir
config report.format
```

Only `ask blindspots`, `ask stealth`, `ask chains`, and `ask check` create saved runs. The directory
is relative to the process working directory unless absolute. An I/O failure is printed but does
not discard the in-memory `last_report`.

`reports export` exports the last in-memory `ask` report. Run the analysis and export it in the same
session. `reports show` is read-only and does not replace the export source.

## Batch mode returned an unexpected exit code

- Without `--fail-on`, findings still exit 0.
- `--fail-on finding` returns 2 only for gap/evasive/stealthy-path/failed-check findings.
- `--fail-on unknown` also returns 4 for exhausted, unknown, or inconclusive output.
- Input and dispatch failures return 3.

The lower-level `decnique-tooling` (`python -m decnique.cli`) has a different contract: 0 success, 1 load/parse issues,
and 3 input errors.

## Personal settings changed during tests

The test suite sets `DECNIQUE_CONFIG` to a temporary path. Outside tests, override it yourself:

```bash
export DECNIQUE_CONFIG=/tmp/decnique-config.json
```

Batch `--report` and `--format` overrides are process-local and do not persist.

## The shell hid an exception

Interactive mode catches input and unexpected errors so the session survives. Reproduce with:

```bash
DECNIQUE_DEBUG=1 python run.py
```

Unexpected exceptions will then be re-raised with a traceback.
