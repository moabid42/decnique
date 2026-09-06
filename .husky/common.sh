# Sourced by the hooks.  A hook runs with your login environment, not your shell's, so the
# project venv is usually *not* activated — put it on PATH ourselves when it is there, and the
# hooks work the same whether or not you remembered to `source .venv/bin/activate`.

for venv in .venv venv .env; do
  if [ -x "./$venv/bin/ruff" ] || [ -x "./$venv/bin/python" ]; then
    PATH="$PWD/$venv/bin:$PATH"
    export PATH
    break
  fi
done

# Tell the author how to get the missing tool instead of failing with "command not found".
need() {  # need <command> <what to run>
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$(basename "$0"): $1 not found."
    echo "  $2"
    return 1
  fi
}
