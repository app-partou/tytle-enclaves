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
npm test
