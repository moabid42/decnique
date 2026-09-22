# Command reference

decnique has two command surfaces:

1. The primary object/verb shell exposed by `run.py` and the installed `decnique` command.
2. A lower-level `decnique-tooling` / `python -m decnique.cli` interface for parsing,
   formatting, importing, and machine-readable compatibility workflows.

## Primary command grammar

```text
<object> <verb> [arguments...]
```

The session holds rules, candidates, checks, events, an account, settings, and the most recent
report. Loading and browsing never invokes a solver. Solver-backed operations are under `ask`.

Typing an object alone runs its default verb:

| Object | Default |
|---|---|
| `rules` | `rules list` |
| `candidates` | `candidates list` |
| `checks` | `checks list` |
| `events` | `events list` |
| `account` | `account show` |
| `catalog` | `catalog perms` |
| `reports` | `reports list` |
| `ask` | none; a solver is never run accidentally |

Loading is additive. When a later interactive load contains the same ID, that item replaces the
session's earlier item while unrelated items remain. Within one load operation, identical repeated
items collapse; conflicting definitions with the same ID are reported as errors.

## `rules`: detection library

### `rules load [--all] [--deprecated] <paths...>`

Load files or recursively scan directories. Recognized inputs are `.decn`, `.yaral`, Elastic
`.toml`, Sigma `.yml`/`.yaml`, Panther `.yml`/`.yaml` with the paired Python rule, and exported
AST `.json`/`.yaml` documents.

- The default keeps GCP-relevant native rules only.
- `--all` disables the platform filter.
- `--deprecated` traverses `_deprecated/` directories and admits deprecated Elastic rules.
- A `.decn` or AST document may also add candidates, checks, and rulesets.

### `rules list [~][substring]`

List loaded detections. A `~` status marks an approximate rule. Use `rules list ~` to show only
approximate rules; add a substring to filter IDs.

### `rules inspect <id>`

Show one rule's canonical DSL, source file and line, frontend, event/correlation shape, metadata,
and every unsupported construct or note recorded by its translator.

### `rules dsl <id>`

Print only canonical DSL, suitable for copying into a `.decn` file.

### `rules admits <method>`

List rules whose event predicates could involve the method. This is a syntactic pre-filter; it
does not assert that the rule fires on every event with that method.

### `rules summary`

Show totals by frontend, exact versus approximate rules, event versus correlation rules,
candidates, checks, load errors/warnings, and common unsupported labels.

## `candidates`: attacker techniques

### `candidates load <paths...>`

Load `.decn` files or directories containing candidates. The shared loader also merges detections
and checks found in those files.

### `candidates list`

List technique IDs, required permissions, footprint steps, and declared gains.

### `candidates inspect <id>`

Show canonical DSL plus required permissions, footprint timing/order, actor/context constraints,
shared fields, and gains.

### `candidates dsl <id>`

Print only the canonical candidate block.

### `candidates footprint [id]`

Match the currently loaded event trace against one or all candidates. The result is yes, no, or
don't-know. Load the trace first with `events load`.

## `checks`: saved assertions

### `checks load <paths...>`

Load check blocks. This never runs them.

### `checks list`

List IDs, types, parameters, and the plain-language question each check asks.

### `checks inspect <id>`

Show a check's canonical DSL, type, options, and question.

### `checks dsl <id>`

Print only the canonical check block.

Run checks with `ask check [id...]`.

## `events`: concrete audit-log traces

### `events load <file.json>`

Load one JSON object or a list of ordered events. Each item can be either a raw Cloud Audit Log
entry with `protoPayload` or an already-normalized event-model dictionary.

### `events list`

List event number, timestamp, method, principal, and resource.

### `events inspect <n>`

Show one event as JSON and evaluate which rules observe it alone. Event numbers shown by the UI
are the identifiers to pass here.

### `events trace [all]`

Evaluate every detection on the complete ordered trace, including joins, windows, ordering, and
aggregates. The default shows rules that fire or are uncertain; `all` also shows definite misses.

### `events observe <file.json>`

Evaluate one event from a file without adding it to the session trace. Output distinguishes event
patterns that observe it, single-event rules that fire, and rules that remain unknown.

## `account`: Reach and Log

### `account load <file.json> [resource]`

Load one of:

- decnique account schema version 1;
- `gcloud projects get-iam-policy ... --format=json` output, with optional `resource` scope;
- `gcloud asset search-all-iam-policies ... --format=json` output;
- `terraform show -json` state or plan;
- native Terraform `*.tf.json` configuration.

The default scope for a plain IAM policy is `*`; pass a concrete value such as
`projects/my-project` for accurate resource scoping. See
[Inputs and integrations](inputs-and-integrations.md) for schema details.

### `account show`

Summarize the account name, principals, expanded grants, resources, hierarchy, deny rules, logging
configuration, access levels, and importer notes.

### `account who [permission | principal [filter]] [--limit N | --all]`

- No argument: list principals and grant/resource counts.
- Permission: list holders, the exact or wildcard grant that supplies it, and its scope.
- Principal: list that principal's grants, optionally filtered by substring or glob.
- Results default to 20 rows; use `--limit N` or `--all`.

## `catalog`: GCP knowledge base

### `catalog perms [filter] [--tag T] [--reachable] [--unwatched] [--limit N | --all]`

Without a filter, summarize permissions by service. With a substring or glob filter, list matching
permissions with method count, logging status, rule mentions, account holders, and attack tag.

- `--tag PrivEsc|CredentialExposure|DataAccess` restricts to a dataset tag.
- `--reachable` keeps permissions reachable in the loaded account.
- `--unwatched` keeps permissions whose methods no loaded rule names.
- The default limit is 20 rows.

### `catalog methods <permission | method> [--limit N]`

For a permission, list every known audit method, service, logging state in the loaded account,
verification status, rule mentions, and required event fields. For a method, show one fact card
with its permissions and realism invariants.

### `catalog roles [filter | role [filter]] [--with permission] [--limit N | --all]`

- No argument or a filter: list predefined roles and tagged-permission counts.
- A complete role name: list the role's permissions, optionally filtered.
- `--with permission`: list roles granting that permission, smallest first.

## `ask`: solver-backed questions

### `ask blindspots [permission...]`

For each requested permission—or every reachable catalog permission when omitted—ask whether any
reachable and logged action evades every rule. Output includes principals, logged methods, a
replayed witness for findings, watched and unwatched change classes, relevant technique verdicts,
and proof/core information when covered.

Verdicts are blind spot, covered, or inconclusive. The `~approx` marker identifies uncertainty.
Settings under `blindspots.*` control explanation style and raw witness display.

### `ask stealth [candidate-id]`

Ask whether one or every candidate can be realized without any rule firing. Outcomes:

- `evasive`: replayed schedule exists;
- `always_detected`: exact evasion constraints are unsatisfiable, with catching rules when available;
- `not_feasible`: no principal holds every required permission;
- `exhausted`: no sound proof or witness was reached within refinement.

Unlogged footprint methods are reported separately as logging gaps.

### `ask chains [goal] [--from principal] [--start p1,p2,...]`

Breadth-first search for a shortest chain of individually stealthy candidates whose `gains` reach
the goal permission. Each accumulated path is replayed as a whole so a cross-hop correlation rule
can reject it.

Defaults come from the account's optional `attack` block. Otherwise the most capable principal is
chosen, its current exact permissions form the initial state, and a goal must be supplied. `--from`
selects the principal; `--start` replaces the starting permission set.

### `ask check [id...]`

Run every loaded check or only the named checks. Every result is `pass`, `fail`, or `unknown`; a
failing existential check includes a replayed witness. See the [DSL reference](dsl-reference.md#checks).

### `ask suggest <permission...> [define]`

For permissions with blind spots, print candidate DSL detections: one per unwatched change class
plus a catch-all over logged methods. With `define`, add them to the current session. Suggestions
optimize modeled coverage and are not automatically production-ready.

## `reports`: durable evidence

### `reports list`

List report files in `report.dir` with verb, timestamp, and summary.

### `reports show <file>`

Re-render a Markdown, JSON, or YAML report: loaded inputs, summary, and findings. Markdown reports
embed their source JSON so they remain machine-reloadable.

### `reports diff <a> <b>`

Compare two reports of the same verb. Show new, closed, and verdict-changed findings.

### `reports export <file.json> [n]`

Export witness events from the last in-memory `ask` run, or only finding `n`, as a JSON list of
Cloud Audit Log entries. Each entry includes `_decnique` provenance. `reports show` is read-only and
does not replace the in-memory run, so export before leaving the session that produced it.

## Shell words

### `help [object [verb]]`

List all objects, an object's verbs, or the detailed page for one verb. Detailed help includes
arguments, output meaning, and relevant settings.

### `config [key [value|reset]]`

- No argument: show every setting, current/default value, choices, and help.
- One key: show that setting.
- Key and value: validate, apply, and persist it.
- Key and `reset`: remove the override.
- Object and optional verb: show its help page and associated settings.

Settings persist at `~/.config/decnique/config.json`; set `DECNIQUE_CONFIG` to override the path.

| Setting | Values | Default | Effect |
|---|---|---|---|
| `blindspots.explain` | `rules`, `formula`, `both`, `words` | `rules` | Explanation style; `words` is an IAM-specific hard-coded vocabulary |
| `blindspots.raw` | `off`, `on` | `off` | Also print complete witness fields |
| `report.save` | `off`, `on` | `off` | Save every solver-backed run |
| `report.format` | `md`, `json`, `yaml` | `md` | Saved report format |
| `report.dir` | free text | `reports` | Output directory relative to the process working directory |

### `clear` and `quit`

`clear` clears the screen without changing session state. `quit` or Ctrl-D leaves the shell.

## Define DSL directly at the prompt

A line starting with `detection`, `candidate`, `check`, or `ruleset` and containing `{` opens a
multiline DSL block. The shell reads until braces balance, parses it, and merges it into the
session. An existing ID is replaced. This enables a complete scratch session without files:

```text
detection watch_policy { event method = "SetIamPolicy" }
candidate touch_policy {
  required { resourcemanager.projects.setIamPolicy }
  footprint { act: "SetIamPolicy" }
}
check policy_covered { type candidate for touch_policy }
ask check policy_covered
```

## Batch launcher

```text
decnique [GLOBAL OPTIONS] <object> <verb> [arguments...]
python run.py [GLOBAL OPTIONS] <object> <verb> [arguments...]
```

| Option | Meaning |
|---|---|
| `--rules PATH...`, `-r PATH...` | Preload rule/DSL paths |
| `--all` | Disable the GCP-only rule filter |
| `--account FILE`, `-a FILE` | Preload account data |
| `--resource RES` | Scope for a plain gcloud IAM policy; default `*` |
| `--json` | Print one report object, or an array for a multi-command script, as JSON |
| `--report DIR` | Save runs to this directory for this process |
| `--format md|json|yaml` | Saved report format |
| `--fail-on finding|unknown` | Enable CI failure policy |
| `--file SCRIPT`, `-f SCRIPT` | Execute one shell command per line; `-` reads stdin |

Exit codes are 0 clean, 2 finding, 3 input error, and 4 inconclusive under
`--fail-on unknown`. Without `--fail-on`, findings do not make the process fail.

## Lower-level `decnique.cli`

Invoke this surface with the installed `decnique-tooling` command. `python -m decnique.cli` is
the equivalent module form:

| Subcommand | Purpose | Important options |
|---|---|---|
| `parse FILES...` | Parse `.decn` and print item counts | `--yaml` also prints the AST document |
| `fmt FILES...` | Print canonical DSL | `--write` rewrites valid files in place |
| `import PATHS... -o DIR` | Translate native rules to one `.decn` file per detection | `--yaml`, `--json`, `--all-platforms`, `--deprecated`, `-v` |
| `load PATHS...` | Load and summarize a corpus | `--list`, platform/deprecated/verbose flags |
| `show FILES...` | Load and print canonical DSL | platform/deprecated/verbose flags |
| `event PATHS... -e EVENT.json` | Emit JSON observation results for one event | common loading flags |
| `trace PATHS... -e EVENTS.json` | Emit rule and candidate results for a trace | `--all-rules` |
| `coverage PATHS... -a ACCOUNT.json` | Emit blindspots, stealth, and optional account-attack chain report | repeatable `--permission` |
| `admits PATHS... -m METHOD` | Print rules that admit a method | `--service` |

This interface returns 0 on success, 1 when load/parse issues exist, and 3 for an input error. It
is useful for tooling and serialization; the object/verb interface is the richer operator UI.
