#!/bin/bash
#
# The PCR0 of a build, beside the record's and the published one
#
# Builds an enclave image with the one recipe of this repository (scripts/lib/recipe.sh), measures its EIF with the
# nitro-cli helper built from verify/Dockerfile.nitro-cli (the helper the verify CLI measures with), and prints its
# PCR0, whether it is the committed build (scripts/expected-digests.json), and the PCR0 that SSM publishes.
#
# It writes nothing. The main repository's enclave reload (infra/scripts/enclave-reload.sh) publishes each pin once its
# enclave runs, with the record checked and the pin it replaces kept as the previous one. The --apply this script had
# wrote any PCR0 it measured: the record unchecked, the commit and the previous pin not kept (enclave review
# 2026-10-09, E2b F-5).
#
# Usage:
#   ./scripts/rotate-pcr0.sh <enclave>    # one enclave
#   ./scripts/rotate-pcr0.sh all          # every enclave
#
# Enclaves: vies, sicae, stripe-payment, monerium-payment. SSM: /tytle/<ENVIRONMENT>/enclave/<key>/pcr0, where
# ENVIRONMENT is staging when it is not set.
#
# Exit status: 0 when every build is its committed build; 1 when a build is not (every enclave asked is still
# printed) or a step failed (a build, a measurement, an SSM read: it stops there); 2 for a usage error.
#
# Prerequisites:
#   - Docker with buildx, and Node.js (the recipe reads its values with it)
#   - AWS CLI configured (the SSM read)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/recipe.sh
source "$REPO_DIR/scripts/lib/recipe.sh"
ENCLAVES=("vies" "sicae" "stripe-payment" "monerium-payment")

# SSM parameter path convention (matches CDK stack: /tytle/{env}/enclave/{key}/pcr0)
ssm_param_name() {
  local enclave="$1"
  local env="${ENVIRONMENT:-staging}"
  local key
  case "$enclave" in
    vies) key="vies" ;;
    sicae) key="sicae" ;;
    stripe-payment) key="stripe_payment" ;;
    monerium-payment) key="monerium_payment" ;;
    *) echo "Unknown enclave: $enclave" >&2; exit 1 ;;
  esac
  echo "/tytle/${env}/enclave/${key}/pcr0"
}

# build_and_measure <enclave> <work dir>: the image's config digest goes to <work>/digest and its EIF's measurements
# to <work>/measurements.json. Every step is checked here: set -e does not reach into a function run as a condition,
# and a failed build used to be measured anyway, as an empty PCR0.
build_and_measure() {
  local enclave="$1" work="$2"
  echo "Building ${enclave} (the recipe: $(recipe_summary))..." >&2
  recipe_build "$enclave" "$work/image.tar" "tytle-enclave-${enclave}:pcr0-check" >&2 || return 1
  recipe_config_digest "$work/image.tar" >"$work/digest" || return 1
  echo "Measuring its EIF..." >&2
  recipe_measure "$work/image.tar" >"$work/measurements.json" || return 1
}

# ssm_pcr0 <name>: the PCR0 SSM publishes under <name>, or "(not set)" when SSM has no such parameter. Any other
# answer fails (an expired session, no permission, another region): it says nothing about the pin.
ssm_pcr0() {
  local answer
  answer="$(aws ssm get-parameters --names "$1" --output json)" || return 1
  node -e '
    const { Parameters = [], InvalidParameters = [] } = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
    if (Parameters.length === 1 && typeof Parameters[0].Value === "string") process.stdout.write(Parameters[0].Value);
    else if (Parameters.length === 0 && InvalidParameters.includes(process.argv[1])) process.stdout.write("(not set)");
    else { process.stderr.write("rotate-pcr0.sh: SSM answered neither the parameter nor that it has none\n"); process.exit(1); }
  ' "$1" <<<"$answer"
}

# rotate_one <enclave>: prints the PCR0 of its build, the record's verdict and SSM's PCR0. Returns 1 when the build is
# not the committed one; a failed step stops the script.
rotate_one() {
  local enclave="$1" work built record param published status=0
  echo "=== ${enclave} ==="
  work="$(mktemp -d)"
  if ! build_and_measure "$enclave" "$work"; then
    rm -rf "$work"
    echo "rotate-pcr0.sh: the build or the measurement of ${enclave} failed: no PCR0" >&2
    exit 1
  fi
  if ! built="$(node "$RECIPE_LIB/recipe.mjs" pcr0 <"$work/measurements.json")"; then
    rm -rf "$work"
    exit 1
  fi
  echo "Built PCR0: ${built}"
  if record="$(node "$RECIPE_LIB/recipe.mjs" check "$enclave" "$(cat "$work/digest")" <"$work/measurements.json" 2>&1)"; then
    echo "Record:     ${record}"
  else
    echo "Record:     NOT the committed build"
    echo "${record}"
    status=1
  fi
  rm -rf "$work"

  param="$(ssm_param_name "$enclave")"
  if ! published="$(ssm_pcr0 "$param")"; then
    echo "rotate-pcr0.sh: the SSM read of ${param} failed" >&2
    exit 1
  fi
  echo "SSM PCR0:   ${published} (${param})"
  if [ "$published" = "$built" ]; then
    echo "SSM has this build."
  else
    echo "SSM has another PCR0. The enclave reload of the main repository publishes this build's once its enclave runs."
  fi
  echo ""
  return "$status"
}

usage() {
  echo "Usage: $0 <enclave|all>" >&2
  echo "Enclaves: ${ENCLAVES[*]}" >&2
}

# Main
enclave="${1:-}"
case "${2:-}" in
  '') ;;
  --apply)
    echo "rotate-pcr0.sh writes no pin. The main repository's enclave reload publishes each pin once its enclave runs," \
      "with the record checked and the pin it replaces kept as the previous one: infra/scripts/enclave-reload.sh." >&2
    exit 2 ;;
  *) usage; exit 2 ;;
esac

targets=()
if [ "$enclave" = "all" ]; then
  targets=("${ENCLAVES[@]}")
else
  for e in "${ENCLAVES[@]}"; do
    if [ "$e" = "$enclave" ]; then targets=("$enclave"); fi
  done
fi
if [ "${#targets[@]}" -eq 0 ]; then
  usage
  exit 2
fi

not_committed=0
for e in "${targets[@]}"; do
  rotate_one "$e" || not_committed=1
done
exit "$not_committed"
