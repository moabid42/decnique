# Getting started

This page takes you from a clean checkout to a useful analysis. Commands assume the repository
root is the current directory.

## Install

Python 3.11 or newer is required. With `uv`:

```bash
uv venv
uv pip install -e .
```

For development, tests, linting, and git hooks:

```bash
uv pip install -e ".[dev]"
.venv/bin/pre-commit install
```

Plain `venv` and `pip install -e ".[dev]"` work as well. The runtime dependencies are Lark,
PyYAML, Z3, Rich, and prompt-toolkit.

Start the interactive shell with either entry point:

```bash
uv run python run.py
# or, after installation
uv run decnique
```

The prompt accepts commands in the form `<object> <verb> [arguments]`. It also accepts complete
DSL blocks beginning with `detection`, `candidate`, `check`, or `ruleset`.

## A self-contained first session

This walkthrough uses the included account and technique library. It defines a deliberately
narrow detection at the prompt, so no external rule corpus is needed.

```text
account load examples/accounts/custom/account.json
candidates load examples/candidates/candidates.decn

detection watch_key_creation {
  event method = "google.iam.admin.v1.CreateServiceAccountKey"
}

rules summary
account who iam.serviceAccountKeys.create
ask blindspots iam.serviceAccountKeys.create
ask stealth create_service_account_key
```

What happened:

1. The account established who can create a service-account key and whether that method is logged.
2. The candidate described the attack's required permission, emitted event, and gain.
3. The detection covered every event whose method is exactly the key-creation method.
4. `ask blindspots` searched all catalogued, reachable, logged uses of the permission.
5. `ask stealth` asked whether that specific one-event technique could be scheduled without a rule firing.

Blindspots and stealth answer different questions. A permission can have some unwatched action or
payload while one specific candidate using it is always detected.

## Use a real rule corpus

decnique does not vendor third-party detection repositories. The optional IAMouflage corpus pins
Google SecOps, Elastic, Sigma, and Panther rule repositories as submodules:

```bash
git clone --recurse-submodules https://github.com/moabid42/IAMouflage.git ../IAMouflage
```

Then run:

```text
rules load ../IAMouflage/data/detections
candidates load examples/candidates/candidates_advanced.decn
checks load examples/checks/checks.decn
account load examples/accounts/custom/account.json

rules summary
rules list ~
ask blindspots resourcemanager.projects.setIamPolicy
ask stealth escalate_owner
ask chains resourcemanager.projects.setIamPolicy
ask check
```

`rules list ~` is important: it shows rules containing untranslated constructs. Inspect one with
`rules inspect <id>` to see its canonical DSL, origin, and `unknown(...)` labels.

## Load and replay real events

The included trace is an ordered list of raw Cloud Audit Log entries:

```text
events load examples/events/events.json
events list
events inspect 1
events trace
candidates footprint
```

- `events trace` evaluates every detection over the whole trace, including correlations.
- `events trace all` also lists rules that return no.
- `candidates footprint [id]` checks whether the trace realizes each candidate's footprint.
- `events observe <file.json>` evaluates one event without adding it to the loaded trace.

## Explore before solving

The catalog and account browsers help construct precise questions:

```text
catalog perms iam.
catalog perms "*.setIamPolicy" --reachable
catalog methods resourcemanager.projects.setIamPolicy
catalog roles --with resourcemanager.projects.setIamPolicy
account who resourcemanager.projects.setIamPolicy
rules admits SetIamPolicy
```

This tells you which principals hold a permission, which method names can exercise it, how those
methods are logged, and which rules could mention them. The `admits` result is a syntactic
pre-filter, not proof that a rule fires.

## Save, compare, and export evidence

Enable reports once in the shell:

```text
config report.save on
config report.format md
config report.dir reports
ask blindspots resourcemanager.projects.setIamPolicy
reports list
```

After changing the rules and rerunning the analysis:

```text
reports diff reports/before.md reports/after.md
reports export witness.json
```

The export is a JSON list of Cloud Audit Log-shaped events. Each carries `_decnique` metadata with
its finding number, label, and verdict. Use it as replay material for your SIEM; it is evidence,
not a claim that the event was actually executed.

`ask suggest <permission>` prints starter DSL detections for uncovered regions. Add `define` to
load those suggestions into the current session, then rerun the question. Suggested rules are
coverage-oriented starting points and still require operational tuning.

## Batch and CI mode

Anything the shell can dispatch can run once and exit:

```bash
uv run python run.py \
  --rules ../IAMouflage/data/detections \
  --account examples/accounts/custom/account.json \
  --json \
  --fail-on finding \
  ask blindspots resourcemanager.projects.setIamPolicy
```

Run a file containing one shell command per line:

```bash
uv run python run.py \
  --rules rules/ \
  --account account.json \
  --report reports \
  --format json \
  --fail-on unknown \
  -f audit.decnique
```

Blank lines and lines beginning with `#` are ignored in command scripts. Exit codes are:

| Code | Meaning |
|---:|---|
| 0 | clean, or no failure policy was requested |
| 2 | a finding exists and `--fail-on finding` or `--fail-on unknown` was requested |
| 3 | command or input error |
| 4 | inconclusive/unknown and `--fail-on unknown` was requested |

## A productive investigation loop

1. Load rules, account, and candidates.
2. Run `rules summary`, `rules list ~`, and `account show` to understand model quality.
3. Browse the target permission with `catalog methods` and `account who`.
4. Use `ask blindspots` for the broad permission question.
5. Use `ask stealth` for a payload-specific attacker technique.
6. Inspect the witness and the watched/unwatched change classes.
7. Use `ask suggest`, write or adjust a real detection, and reload it.
8. Rerun and use `reports diff` to confirm what changed.
9. Export the witness and replay it in the destination SIEM before operational rollout.

Continue with the [Command reference](command-reference.md) or learn to write your own
[DSL definitions](dsl-reference.md). Before using findings operationally, read
[Concepts and verdicts](concepts-and-verdicts.md).
