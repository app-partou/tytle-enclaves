#!/usr/bin/env bash
#
# The determinism gate (enclave audit P2.2). Each enclave image, built twice from scratch with the one recipe
# (scripts/lib/recipe.sh), must be the same image both times AND the build committed in scripts/expected-digests.json:
# the same config digest and the same EIF measurements (PCR0, PCR1, PCR2, from the pinned nitro-cli helper).
# An image that changes is a PCR0 that changes: a change that means it records the new build (--update) and commits
# the file, so the pull request shows every PCR0 it changes. CI runs this for each enclave on every pull request.
#
# Usage:
#   ./scripts/test-determinism.sh                   # every enclave
#   ./scripts/test-determinism.sh vies              # one enclave
#   ./scripts/test-determinism.sh --update [vies]   # build twice, then record the build in expected-digests.json
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/recipe.sh
source "$REPO_DIR/scripts/lib/recipe.sh"

ENCLAVES=("vies" "sicae" "stripe-payment" "monerium-payment")
UPDATE_MODE=false

for arg in "$@"; do
  case "$arg" in
    --update) UPDATE_MODE=true ;;
    vies|sicae|stripe-payment|monerium-payment) ENCLAVES=("$arg") ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "The recipe: $(recipe_summary)"

FAIL=0
for enclave in "${ENCLAVES[@]}"; do
  echo ""
  echo "=== ${enclave} ==="
  a="$WORK/${enclave}-a.tar"
  b="$WORK/${enclave}-b.tar"
  recipe_build "$enclave" "$a" "tytle-enclave-${enclave}:determinism-a" --no-cache
  recipe_build "$enclave" "$b" "tytle-enclave-${enclave}:determinism-b" --no-cache
  digest_a="$(recipe_config_digest "$a")"
  digest_b="$(recipe_config_digest "$b")"
  echo "Build A: ${digest_a}"
  echo "Build B: ${digest_b}"
  if [ "$digest_a" != "$digest_b" ]; then
    echo "FAIL: ${enclave} - two builds of the same source are two different images"
    FAIL=$((FAIL + 1))
    continue
  fi

  measurements="$(recipe_measure "$a")"
  docker rmi "tytle-enclave-${enclave}:determinism-a" >/dev/null 2>&1 || true
  echo "PCR0: $(node "$RECIPE_LIB/recipe.mjs" pcr0 <<<"$measurements")"

  if [ "$UPDATE_MODE" = true ]; then
    node "$RECIPE_LIB/recipe.mjs" record "$enclave" "$digest_a" <<<"$measurements"
  elif node "$RECIPE_LIB/recipe.mjs" check "$enclave" "$digest_a" <<<"$measurements"; then
    echo "PASS: ${enclave}"
  else
    FAIL=$((FAIL + 1))
  fi
done

echo ""
echo "=== $(( ${#ENCLAVES[@]} - FAIL )) passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ]
