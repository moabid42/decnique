## What and why

<!-- One or two sentences. The commit subject line, expanded. -->

## Checks

- [ ] `ruff check .` is clean
- [ ] `pytest` is green (add `-m "not e2e"` for the fast loop)
- [ ] a test covers the behaviour change, and its docstring says what breaks if it fails
- [ ] no new runtime dependency (`AGENTS.md` §8)

## Invariants (`AGENTS.md` §5)

- [ ] nothing untranslatable became `true` or `false` — it became `unknown(...)` and the result
      is flagged approximate
- [ ] every returned witness is still replayed through the concrete oracle
- [ ] `parse(format(x)) == x` still holds

## Notes for the reviewer

<!-- Anything surprising: a verdict that changed, a rule that is now approximate, a slower path. -->
