#!/bin/bash
# Regenerate vendored Alpine .apk files for the rust-builder stage.
#
# Runs inside the pinned rust:1.83-alpine base image to compute the exact
# dependency closure for `musl-dev nodejs npm`, then fetches each package
# from the Alpine mirror. After running, commit the updated .apk files and
# SHASUMS256.txt together.
#
# Usage: ./regenerate.sh

set -euo pipefail

# Must match the digest used in all 4 enclave Dockerfiles.
# If you bump the rust:1.83-alpine digest in the Dockerfiles, update this too
# and re-run to regenerate the .apk files for the new base image.
RUST_BUILDER_IMAGE="rust:1.83-alpine@sha256:0ac946ed7597a9f053a1be2ce38c09aa88b3d7079a91ea491493615294b1f699"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Regenerating vendored apk files from ${RUST_BUILDER_IMAGE}"
echo "Target directory: ${SCRIPT_DIR}"
echo

# Remove old .apk files (keep SHASUMS256.txt, README.md, this script).
rm -f "${SCRIPT_DIR}"/*.apk

# Do the simulate + fetch in a single docker run so both operations share
# the same apk index cache (no race between pulling index and fetching .apk).
#
# apk add --simulate output:
#   (1/13) Upgrading musl (1.2.5-r8 -> 1.2.5-r11)
#   (2/13) Installing musl-dev (1.2.5-r11)
#
# We extract $3 (the package name) from each Installing/Upgrading line, then
# loop over those names and call `apk fetch <name>` individually. Without -R
# (recursive), apk fetches just that one package without its deps - safe
# because `apk add --simulate` already gave us the complete closure.
#
# Everything that needs tool parity with the Dockerfile's verification step
# (apk, awk, sha256sum, sort) runs INSIDE the pinned rust:1.83-alpine container.
# This keeps the script portable between macOS (where `sha256sum` isn't in the
# default PATH - only `shasum` is) and Linux (where `sha256sum` is standard),
# and also guarantees bit-identical output to what sha256sum -c sees at build
# time inside the container.
docker run --rm --platform linux/amd64 -v "${SCRIPT_DIR}:/out" "${RUST_BUILDER_IMAGE}" sh -eu -c '
  apk update >/dev/null 2>&1

  pkgs=$(apk add --simulate --no-cache musl-dev nodejs npm 2>&1 \
    | awk "/^\\([0-9]+\\/[0-9]+\\) (Installing|Upgrading)/ { print \$3 }")

  if [ -z "$pkgs" ]; then
    echo "ERROR: Could not compute package list" >&2
    exit 1
  fi

  echo "Package closure:"
  echo "$pkgs" | sed "s/^/  /"
  echo

  cd /out
  for p in $pkgs; do
    apk fetch --no-cache "$p" >/dev/null || {
      echo "ERROR: failed to fetch $p" >&2
      exit 1
    }
  done

  echo
  echo "Fetched files:"
  ls -la /out/*.apk
  echo

  # Rebuild checksums deterministically (LC_ALL=C for reproducible sort).
  # sha256sum runs inside the Alpine container (BusyBox coreutils) so the
  # output format matches what the Dockerfile uses at build time.
  cd /out
  LC_ALL=C sha256sum *.apk | LC_ALL=C sort > SHASUMS256.txt

  echo "New SHASUMS256.txt:"
  cat SHASUMS256.txt
'

echo
echo "Done. Review the diff and commit the .apk files together with SHASUMS256.txt."
