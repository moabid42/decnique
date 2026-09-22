# decnique

**A formal language and evaluation framework for measuring detection coverage against adversarial
techniques.**

decnique determines whether actions that are reachable in a specific Google Cloud account and
present in its audit logs are observed by a concrete SIEM rule corpus. It translates Google
SecOps/YARA-L, Elastic, Sigma, and Panther rules into one shared model, combines symbolic analysis
with concrete replay, and exposes the results through an interactive shell and CI-friendly batch
commands.

## Documentation

The complete documentation is maintained in the
**[GitHub Wiki](https://github.com/moabid42/decnique/wiki)**:

- [Getting started](https://github.com/moabid42/decnique/wiki/getting-started)
- [Command reference](https://github.com/moabid42/decnique/wiki/command-reference)
- [DSL reference](https://github.com/moabid42/decnique/wiki/dsl-reference)
- [Analysis guide](https://github.com/moabid42/decnique/wiki/analysis-guide)
- [Inputs and integrations](https://github.com/moabid42/decnique/wiki/inputs-and-integrations)
- [Architecture](https://github.com/moabid42/decnique/wiki/architecture)
- [Cookbook](https://github.com/moabid42/decnique/wiki/cookbook)
- [Troubleshooting](https://github.com/moabid42/decnique/wiki/troubleshooting)
- [Development guide](https://github.com/moabid42/decnique/wiki/development)

Repository-specific contributor instructions remain in [AGENTS.md](AGENTS.md) and validation/setup
details in [CONTRIBUTING.md](CONTRIBUTING.md).

## What it answers

- **Blindspots:** can any reachable, logged use of a permission evade every loaded detection?
- **Stealth:** can a specific attacker technique and payload execute without a rule firing?
- **Chains:** can stealthy techniques compose into a privilege-escalation path?
- **Checks:** do saved coverage, boundary, comparison, redundancy, dead-rule, and public-access
  assertions pass, fail, or remain unknown?

The core single-event question is:

```text
∃ e : Reach_p(e) ∧ Log(e) ∧ ¬(⋁_R Observes(R, e))
```

Answers are three-valued. Unsupported native-rule semantics remain explicit `unknown(...)` atoms,
and every symbolic witness is replayed through the concrete evaluator before it is reported.

## Quick start

Python 3.11 or newer is required:

```bash
uv venv
uv pip install -e .
uv run decnique
```

Inside the shell:

```text
rules load ../IAMouflage/data/detections
candidates load examples/candidates/candidates.decn
checks load examples/checks/checks.decn
account load examples/accounts/custom/account.json

ask blindspots resourcemanager.projects.setIamPolicy
ask stealth escalate_project_iam
ask chains
ask check
```

The repository does not vendor third-party rule corpora. The optional
[IAMouflage](https://github.com/moabid42/IAMouflage) corpus can be cloned next to this repository:

```bash
git clone --recurse-submodules https://github.com/moabid42/IAMouflage.git ../IAMouflage
```

See the Wiki's [Getting started](https://github.com/moabid42/decnique/wiki/getting-started) page for
account imports, event replay, reports, batch mode, exit codes, and a self-contained walkthrough.

## Development

```bash
uv pip install -e ".[dev]"
.venv/bin/pre-commit install
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
```

Implemented changes and planned work are tracked in [CHANGELOG.md](CHANGELOG.md). The
[development guide](https://github.com/moabid42/decnique/wiki/development) covers extension recipes
for frontends, event fields, catalogs, checks, commands, settings, and solver engines.
