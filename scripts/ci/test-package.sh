#!/usr/bin/env bash
#
# CI: one package's tests on a clean checkout (enclave audit P2.2; .github/workflows/ci.yml runs it for each). The
# tests of every package but verify import shared's sources - their vitest configs point @tytle-enclaves/shared at
# ../shared/src and the native addon at a stub - so shared's dependencies are installed first.
#
# Usage: scripts/ci/test-package.sh <shared|parent|vies|sicae|stripe-payment|monerium-payment|verify>
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PACKAGE="${1:-}"
case "$PACKAGE" in
  shared|parent|vies|sicae|stripe-payment|monerium-payment|verify) ;;
  *) echo "Usage: $0 <shared|parent|vies|sicae|stripe-payment|monerium-payment|verify>" >&2; exit 2 ;;
esac

if [ "$PACKAGE" != verify ]; then
  npm ci --prefix "$REPO_DIR/shared" --no-audit --no-fund
fi
if [ "$PACKAGE" != shared ]; then
  npm ci --prefix "$REPO_DIR/$PACKAGE" --no-audit --no-fund
fi
cd "$REPO_DIR/$PACKAGE"
# The verify CLI is what a third party builds (VERIFICATION.md: npm ci, npm run build): its compiler runs here, so
# a type error fails CI, not their build (enclave review 2026-10-09, E2b F-7). vitest runs sources uncompiled.
if [ "$PACKAGE" = verify ]; then
  npm run build
fi
npm test
