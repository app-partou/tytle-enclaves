#!/usr/bin/env bash
#
# Build one enclave's EIF - the file a Nitro host runs - with the one recipe of this repository (scripts/lib/recipe.sh),
# check that it is the committed build (scripts/expected-digests.json: its image config digest, PCR0, PCR1 and PCR2),
# and only then write <out-dir>/<enclave>.eif and <out-dir>/<enclave>.measurements.json (enclave audit P1.6).
#
# Signed when EIF_SIGNING_KEY and EIF_SIGNING_CERT name the signing key and its certificate (PEM files, both or
# neither; recipe_measure checks the certificate first). A signed EIF carries PCR8, the certificate's, and every other
# PCR of the unsigned build: it is still the committed build. This is the build the deploy is to run in CI with the
# signing certificate of gate G7, shipping the EIF and its measurements to the host, which only downloads and runs
# them and never holds the key.
#
# Usage:
#   EIF_SIGNING_KEY=key.pem EIF_SIGNING_CERT=cert.pem scripts/build-eif.sh <enclave> <out-dir>   # signed
#   scripts/build-eif.sh <enclave> <out-dir>                                                    # unsigned
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/recipe.sh
source "$REPO_DIR/scripts/lib/recipe.sh"

ENCLAVE="${1:-}"
OUT_DIR="${2:-}"
case "$ENCLAVE" in
  ''|*[!a-z-]*) ENCLAVE="" ;;
esac
if [ -z "$ENCLAVE" ] || [ ! -f "$REPO_DIR/$ENCLAVE/src/enclave.ts" ] || [ -z "$OUT_DIR" ]; then
  echo "Usage: $0 <enclave> <out-dir>  (an enclave is a directory of this repository with src/enclave.ts)" >&2
  exit 2
fi
mkdir -p "$OUT_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
IMAGE="tytle-enclave-${ENCLAVE}:eif"

# A certificate that cannot sign stops here, before a build of minutes
recipe_signing_pcr8 >/dev/null

echo "Building ${ENCLAVE} (the recipe: $(recipe_summary))" >&2
recipe_build "$ENCLAVE" "$WORK/image.tar" "$IMAGE" >&2
digest="$(recipe_config_digest "$WORK/image.tar")"
measurements="$(recipe_measure "$WORK/image.tar" "$WORK/${ENCLAVE}.eif")"
docker rmi "$IMAGE" >/dev/null 2>&1 || true
node "$RECIPE_LIB/recipe.mjs" check "$ENCLAVE" "$digest" <<<"$measurements" >&2

mv "$WORK/${ENCLAVE}.eif" "$OUT_DIR/${ENCLAVE}.eif"
node "$RECIPE_LIB/recipe.mjs" eif-measurements "$ENCLAVE" "$digest" <<<"$measurements" \
  > "$OUT_DIR/${ENCLAVE}.measurements.json"
echo "EIF: $OUT_DIR/${ENCLAVE}.eif" >&2
cat "$OUT_DIR/${ENCLAVE}.measurements.json"
