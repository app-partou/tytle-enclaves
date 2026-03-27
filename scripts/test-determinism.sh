#!/usr/bin/env bash
#
# Test enclave build determinism.
#
# 1. Builds each enclave image TWICE with the same SOURCE_DATE_EPOCH
# 2. Asserts both builds produce identical image digests
# 3. Optionally checks against stored expected digests (scripts/expected-digests.json)
#
# Usage:
#   ./scripts/test-determinism.sh              # Test all enclaves
#   ./scripts/test-determinism.sh vies         # Test single enclave
#   ./scripts/test-determinism.sh --update     # Build once and update expected digests
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED_FILE="$REPO_DIR/scripts/expected-digests.json"
SOURCE_DATE_EPOCH=$(git -C "$REPO_DIR" log -1 --pretty=%ct)
export SOURCE_DATE_EPOCH

ENCLAVES=("vies" "sicae" "stripe-payment")
UPDATE_MODE=false

# Parse args
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE_MODE=true ;;
    vies|sicae|stripe-payment) ENCLAVES=("$arg") ;;
  esac
done

build_enclave() {
  local name=$1
  local tag=$2
  docker buildx build \
    --output type=docker,rewrite-timestamp=true \
    --platform linux/amd64 \
    --no-cache \
    -t "tytle-enclave-${name}:${tag}" \
    -f "$REPO_DIR/${name}/Dockerfile" \
    "$REPO_DIR" 2>&1
  docker inspect --format='{{.Id}}' "tytle-enclave-${name}:${tag}"
}

PASS=0
FAIL=0
RESULTS="{}"

for enclave in "${ENCLAVES[@]}"; do
  echo ""
  echo "============================================================"
  echo "  Testing: $enclave"
  echo "============================================================"

  if [ "$UPDATE_MODE" = true ]; then
    echo "  Building (update mode)..."
    digest=$(build_enclave "$enclave" "determinism-test" | tail -1)
    echo "  Digest: $digest"
    RESULTS=$(echo "$RESULTS" | node -e "
      const d = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
      d['$enclave'] = { digest: '$digest', source_date_epoch: $SOURCE_DATE_EPOCH, updated: new Date().toISOString().slice(0,10) };
      console.log(JSON.stringify(d, null, 2));
    ")
    docker rmi "tytle-enclave-${enclave}:determinism-test" >/dev/null 2>&1 || true
    PASS=$((PASS + 1))
    continue
  fi

  # Build A
  echo "  Build A..."
  digest_a=$(build_enclave "$enclave" "determinism-a" | tail -1)
  echo "  Digest A: $digest_a"

  # Build B
  echo "  Build B..."
  digest_b=$(build_enclave "$enclave" "determinism-b" | tail -1)
  echo "  Digest B: $digest_b"

  # Determinism check
  if [ "$digest_a" = "$digest_b" ]; then
    echo "  PASS: Builds are identical"
  else
    echo "  FAIL: Builds differ!"
    echo "    A: $digest_a"
    echo "    B: $digest_b"
    FAIL=$((FAIL + 1))
    # Clean up and skip regression check
    docker rmi "tytle-enclave-${enclave}:determinism-a" "tytle-enclave-${enclave}:determinism-b" >/dev/null 2>&1 || true
    continue
  fi

  # Regression check against expected digests
  if [ -f "$EXPECTED_FILE" ]; then
    expected=$(node -e "
      const d = JSON.parse(require('fs').readFileSync('$EXPECTED_FILE','utf8'));
      const e = d['$enclave'];
      if (e && e.source_date_epoch === $SOURCE_DATE_EPOCH) {
        console.log(e.digest);
      } else {
        console.log('SKIP');
      }
    ")
    if [ "$expected" = "SKIP" ]; then
      echo "  SKIP regression: SOURCE_DATE_EPOCH changed (expected digests are for a different commit)"
    elif [ "$digest_a" = "$expected" ]; then
      echo "  PASS: Matches expected digest"
    else
      echo "  WARN: Digest changed from expected (update with --update if intentional)"
      echo "    Expected: $expected"
      echo "    Got:      $digest_a"
    fi
  fi

  PASS=$((PASS + 1))

  # Clean up
  docker rmi "tytle-enclave-${enclave}:determinism-a" "tytle-enclave-${enclave}:determinism-b" >/dev/null 2>&1 || true
done

if [ "$UPDATE_MODE" = true ]; then
  echo "$RESULTS" > "$EXPECTED_FILE"
  echo ""
  echo "Updated $EXPECTED_FILE"
  cat "$EXPECTED_FILE"
fi

echo ""
echo "============================================================"
echo "  Results: $PASS passed, $FAIL failed"
echo "============================================================"

[ "$FAIL" -eq 0 ]
