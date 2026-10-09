# shellcheck shell=bash
#
# The ONE build recipe of every image of this repository (enclave audit P2.2). Sourced, never run: each service's
# build.sh (the deploy), scripts/test-determinism.sh (the determinism gate and CI), scripts/build-eif.sh (an EIF,
# signed or not) and scripts/rotate-pcr0.sh build and measure through these functions and nothing else.
#
# The values are scripts/build-recipe.json's:
#   - platform: linux/amd64, what a Nitro host runs.
#   - sourceDateEpoch: a FIXED time, not the commit's. BuildKit's rewrite-timestamp sets every file newer than it to
#     it, so an image - and its PCR0 - changes only when what goes into it changes. Until 2026-10 it was the time of
#     the newest commit: every commit, a README edit too, changed every PCR0, and no digest could be committed.
#   - buildkitImage: the BuildKit that builds, pinned by digest and run as this repository's own docker-container
#     builder (never made the default builder). The layers and their file times are BuildKit's work: another BuildKit
#     version can give another image, and so another PCR0.
# The image goes to a docker tarball (type=docker,dest=...): Docker's containerd image store (Docker Desktop's
# default) refuses rewrite-timestamp on a direct load ("rewrite-timestamp conflicts with unpack"). Provenance and SBOM
# attestations are off: they are not part of the image, and a docker tarball cannot hold them.
#
# The verify CLI holds the same values (verify/src/lib/buildRecipe.ts) and never runs this file: a verifier does not
# run the verified repository's code on their own host. verify's buildRecipe.drift.test.ts keeps the two equal.

RECIPE_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECIPE_REPO_DIR="$(cd "$RECIPE_LIB/../.." && pwd)"

recipe_value() { node "$RECIPE_LIB/recipe.mjs" value "$1"; }

# A line for logs: what this build is.
recipe_summary() {
  echo "$(recipe_value platform), SOURCE_DATE_EPOCH=$(recipe_value sourceDateEpoch), $(recipe_value buildkitImage)"
}

# The name of the pinned BuildKit's builder, made on first use.
recipe_builder() {
  local name
  name="$(node "$RECIPE_LIB/recipe.mjs" builder-name)"
  if ! docker buildx inspect "$name" >/dev/null 2>&1; then
    # Another build may make it at the same moment: then it exists, and that is all this needs.
    docker buildx create --name "$name" --driver docker-container \
      --driver-opt "image=$(recipe_value buildkitImage)" >/dev/null \
      || docker buildx inspect "$name" >/dev/null
  fi
  echo "$name"
}

# recipe_build <service> <out.tar> <image-name> [buildx flags, e.g. --no-cache]
# Builds <service>/Dockerfile with the whole repository as its context into a docker tarball of one image.
recipe_build() {
  local service="$1" out="$2" name="$3" builder
  shift 3
  if [ ! -f "$RECIPE_REPO_DIR/$service/Dockerfile" ]; then
    echo "recipe_build: there is no $service/Dockerfile" >&2
    return 1
  fi
  builder="$(recipe_builder)"
  SOURCE_DATE_EPOCH="$(recipe_value sourceDateEpoch)" docker buildx build \
    --builder "$builder" \
    --platform "$(recipe_value platform)" \
    --provenance=false --sbom=false \
    --output "type=docker,dest=$out,rewrite-timestamp=true,name=$name" \
    -f "$RECIPE_REPO_DIR/$service/Dockerfile" \
    "$@" \
    "$RECIPE_REPO_DIR"
}

# recipe_config_digest <out.tar> - the image's config digest (sha256:...), the same on every Docker image store.
recipe_config_digest() { tar -xOf "$1" manifest.json | node "$RECIPE_LIB/recipe.mjs" config-digest; }

# The nitro-cli helper (verify/Dockerfile.nitro-cli, built for the recipe's platform) - the image the verify CLI
# measures with, under the same tag. Built for that platform on every host: on an arm64 host (an Apple Silicon Mac)
# an arm64 nitro-cli looks for an arm64 image and fails with E48.
recipe_nitro_helper() {
  local tag context
  tag="$(node "$RECIPE_LIB/recipe.mjs" helper-tag)"
  if ! docker image inspect "$tag" >/dev/null 2>&1; then
    context="$(mktemp -d)"   # the Dockerfile copies nothing: an empty context
    docker build --platform "$(recipe_value platform)" -t "$tag" \
      -f "$RECIPE_REPO_DIR/verify/Dockerfile.nitro-cli" "$context" >&2
    rmdir "$context"
  fi
  echo "$tag"
}

# recipe_signing_pcr8 - the EIF signing key and certificate (enclave audit P1.6): EIF_SIGNING_KEY and EIF_SIGNING_CERT
# name them, PEM files, both or neither. With neither it prints nothing: the EIF is unsigned. With both it checks the
# certificate (EC P-384, the key's own, valid, at least 60 days left: an EIF whose certificate has expired does not
# start, and neither does a restart of it) and prints the PCR8 an EIF it signs carries. Call it before building.
recipe_signing_pcr8() {
  if [ -z "${EIF_SIGNING_KEY:-}${EIF_SIGNING_CERT:-}" ]; then
    return 0
  fi
  if [ -z "${EIF_SIGNING_KEY:-}" ] || [ -z "${EIF_SIGNING_CERT:-}" ]; then
    echo "recipe: set both EIF_SIGNING_KEY and EIF_SIGNING_CERT, or neither" >&2
    return 1
  fi
  node "$RECIPE_LIB/recipe.mjs" signing-check "$EIF_SIGNING_CERT" "$EIF_SIGNING_KEY"
}

# recipe_measure <out.tar> [out.eif] - loads the image into Docker, makes its EIF with the nitro-cli helper and prints
# the EIF's measurements: {"pcr0","pcr1","pcr2"}, and "pcr8" when it is signed. Given out.eif (its directory must
# exist), the EIF is kept there; else it is gone with the helper.
#
# Signed when the signing key and certificate are set (recipe_signing_pcr8, checked again here): both files are
# mounted read-only, and the EIF's PCR8 must be the certificate's. Signing changes no other PCR: PCR0, PCR1 and PCR2
# are the unsigned build's, what a third party's rebuild gives. PCR8 says whose signed EIF ran.
recipe_measure() {
  local tar="$1" eif="${2:-}" name helper pcr8 measurements
  pcr8="$(recipe_signing_pcr8)" || return 1
  name="$(tar -xOf "$tar" manifest.json | node "$RECIPE_LIB/recipe.mjs" image-name)" || return 1
  docker load -i "$tar" >/dev/null || return 1
  helper="$(recipe_nitro_helper)" || return 1

  # The helper's arguments, in order (positional: an empty array is an unbound variable on bash 3.2 with set -u)
  set -- --rm --platform "$(recipe_value platform)" -v /var/run/docker.sock:/var/run/docker.sock
  if [ -n "$pcr8" ]; then
    set -- "$@" -v "$(recipe_abs_path "$EIF_SIGNING_KEY"):/signing/key.pem:ro" \
      -v "$(recipe_abs_path "$EIF_SIGNING_CERT"):/signing/cert.pem:ro"
  fi
  if [ -n "$eif" ]; then
    set -- "$@" -v "$(recipe_abs_path "$(dirname "$eif")"):/out" \
      "$helper" build-enclave --docker-uri "$name" --output-file "/out/$(basename "$eif")"
  else
    set -- "$@" "$helper" build-enclave --docker-uri "$name" --output-file /tmp/measure.eif
  fi
  if [ -n "$pcr8" ]; then
    set -- "$@" --private-key /signing/key.pem --signing-certificate /signing/cert.pem
  fi

  measurements="$(docker run "$@" | node "$RECIPE_LIB/recipe.mjs" measurements)" || return 1
  if [ -n "$pcr8" ]; then
    node "$RECIPE_LIB/recipe.mjs" pcr8-is "$pcr8" <<<"$measurements" >/dev/null || return 1
  fi
  echo "$measurements"
}

# recipe_abs_path <path> - the absolute path of a file or directory that exists (docker -v takes no relative path).
recipe_abs_path() {
  if [ -d "$1" ]; then
    (cd "$1" && pwd)
  else
    echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
  fi
}
