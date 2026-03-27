#!/usr/bin/env bash
#
# Generate pre-stripped package.docker.json + package-lock.docker.json
# for deterministic Docker builds (npm ci instead of npm install).
#
# Run this after changing dependencies in any enclave package:
#   ./scripts/generate-docker-lockfiles.sh
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

strip_deps_for() {
  case "$1" in
    shared) echo "@tytle-enclaves/native" ;;
    *)      echo "@tytle-enclaves/native @tytle-enclaves/shared" ;;
  esac
}

for pkg in shared vies sicae stripe-payment; do
  pkg_dir="$REPO_ROOT/$pkg"
  echo "=== $pkg ==="

  if [ ! -f "$pkg_dir/package.json" ]; then
    echo "  SKIP: no package.json"
    continue
  fi

  deps_to_strip=$(strip_deps_for "$pkg")

  tmp_dir=$(mktemp -d)
  cp "$pkg_dir/package.json" "$tmp_dir/package.json"
  cp "$pkg_dir/package-lock.json" "$tmp_dir/package-lock.json"

  # Strip file: deps from package.json only. Delete the lockfile and let
  # npm regenerate it cleanly from the stripped package.json.
  DEPS_TO_STRIP="$deps_to_strip" TMP_DIR="$tmp_dir" node -e '
    const fs = require("fs");
    const depsToStrip = process.env.DEPS_TO_STRIP.split(" ");
    const dir = process.env.TMP_DIR;

    const pkg = JSON.parse(fs.readFileSync(dir + "/package.json", "utf8"));
    for (const dep of depsToStrip) {
      delete pkg.dependencies?.[dep];
    }
    fs.writeFileSync(dir + "/package.json", JSON.stringify(pkg, null, 2) + "\n");
  '

  # Generate a fresh lockfile from the stripped package.json.
  # Empty .npmrc prevents npm from walking up to a parent workspace.
  rm "$tmp_dir/package-lock.json"
  touch "$tmp_dir/.npmrc"
  (cd "$tmp_dir" && npm install --package-lock-only --ignore-scripts)

  # Copy results
  cp "$tmp_dir/package.json" "$pkg_dir/package.docker.json"
  cp "$tmp_dir/package-lock.json" "$pkg_dir/package-lock.docker.json"
  rm -rf "$tmp_dir"

  echo "  -> package.docker.json"
  echo "  -> package-lock.docker.json"
done

echo ""
echo "Done. Verify with: git diff --stat"
