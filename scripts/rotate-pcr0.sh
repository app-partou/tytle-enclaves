#!/bin/bash
#
# PCR0 Rotation Helper
#
# Builds an enclave image with the one recipe of this repository (scripts/lib/recipe.sh), measures its EIF with the
# nitro-cli helper built from verify/Dockerfile.nitro-cli (the helper the verify CLI measures with), and optionally
# updates the SSM parameter. scripts/expected-digests.json holds the same PCR0 for the committed build.
#
# Usage:
#   ./scripts/rotate-pcr0.sh <enclave>           # Print old vs new PCR0
#   ./scripts/rotate-pcr0.sh <enclave> --apply    # Also update SSM parameter
#   ./scripts/rotate-pcr0.sh all                  # Print PCR0 for all enclaves
#
# Enclaves: vies, sicae, stripe-payment, monerium-payment
#
# Prerequisites:
#   - Docker with buildx, and Node.js (the recipe reads its values with it)
#   - AWS CLI configured (for --apply and SSM lookup)

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

build_and_extract_pcr0() {
  local enclave="$1" work pcr0
  work="$(mktemp -d)"

  echo "Building ${enclave} (the recipe: $(recipe_summary))..." >&2
  recipe_build "$enclave" "$work/image.tar" "tytle-enclave-${enclave}:pcr0-check" >&2

  echo "Measuring its EIF..." >&2
  pcr0="$(recipe_measure "$work/image.tar" | node "$RECIPE_LIB/recipe.mjs" pcr0)"
  rm -rf "$work"
  echo "$pcr0"
}

get_current_ssm_pcr0() {
  local param_name="$1"
  aws ssm get-parameter --name "$param_name" --query 'Parameter.Value' --output text 2>/dev/null || echo "(not set)"
}

rotate_one() {
  local enclave="$1"
  local apply="${2:-}"

  echo "=== ${enclave} ==="

  local new_pcr0
  new_pcr0=$(build_and_extract_pcr0 "$enclave")
  echo "New PCR0: ${new_pcr0}"

  local param_name
  param_name=$(ssm_param_name "$enclave")
  local current_pcr0
  current_pcr0=$(get_current_ssm_pcr0 "$param_name")
  echo "SSM PCR0: ${current_pcr0} (${param_name})"

  if [ "$new_pcr0" = "$current_pcr0" ]; then
    echo "No change."
  else
    echo "CHANGED"
    if [ "$apply" = "--apply" ]; then
      echo "Updating SSM parameter ${param_name}..."
      aws ssm put-parameter \
        --name "$param_name" \
        --value "$new_pcr0" \
        --type String \
        --overwrite
      echo "Updated."
    else
      echo "Run with --apply to update SSM."
    fi
  fi
  echo ""
}

# Main
enclave="${1:-}"
apply="${2:-}"

if [ -z "$enclave" ]; then
  echo "Usage: $0 <enclave|all> [--apply]"
  echo "Enclaves: ${ENCLAVES[*]}"
  exit 1
fi

if [ "$enclave" = "all" ]; then
  for e in "${ENCLAVES[@]}"; do
    rotate_one "$e" "$apply"
  done
else
  rotate_one "$enclave" "$apply"
fi
