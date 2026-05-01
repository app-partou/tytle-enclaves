#!/bin/bash
#
# PCR0 Rotation Helper
#
# Builds an enclave Docker image, extracts its PCR0 by converting to EIF
# via a pinned nitro-cli Docker image, and optionally updates the SSM parameter.
#
# Usage:
#   ./scripts/rotate-pcr0.sh <enclave>           # Print old vs new PCR0
#   ./scripts/rotate-pcr0.sh <enclave> --apply    # Also update SSM parameter
#   ./scripts/rotate-pcr0.sh all                  # Print PCR0 for all enclaves
#
# Enclaves: vies, sicae, stripe-payment
#
# Prerequisites:
#   - Docker with BuildKit
#   - AWS CLI configured (for --apply and SSM lookup)

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENCLAVES=("vies" "sicae" "stripe-payment")

# Pinned nitro-cli image for reproducible PCR0 extraction (no Nitro instance needed)
NITRO_CLI_IMAGE="docker.io/tytle/nitro-cli:1.4.4"

# SSM parameter path convention (matches CDK stack: /tytle/{env}/enclave/{key}/pcr0)
ssm_param_name() {
  local enclave="$1"
  local env="${ENVIRONMENT:-staging}"
  local key
  case "$enclave" in
    vies) key="vies" ;;
    sicae) key="sicae" ;;
    stripe-payment) key="stripe_payment" ;;
    *) echo "Unknown enclave: $enclave" >&2; exit 1 ;;
  esac
  echo "/tytle/${env}/enclave/${key}/pcr0"
}

build_and_extract_pcr0() {
  local enclave="$1"
  local image_tag="tytle-enclave-${enclave}:pcr0-check"

  echo "Building ${enclave}..." >&2
  local source_epoch
  source_epoch=$(git -C "$REPO_DIR" log -1 --pretty=%ct)

  SOURCE_DATE_EPOCH="$source_epoch" docker buildx build \
    --output type=docker,rewrite-timestamp=true \
    --platform linux/amd64 \
    -t "$image_tag" \
    -f "${REPO_DIR}/${enclave}/Dockerfile" \
    "$REPO_DIR" >&2

  echo "Extracting PCR0 from EIF..." >&2
  # Convert Docker image to EIF and extract PCR0 using pinned nitro-cli
  local pcr0
  pcr0=$(docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    "$NITRO_CLI_IMAGE" \
    build-enclave --docker-uri "$image_tag" --output-file /dev/null 2>&1 \
    | grep -oP '"PCR0":\s*"\K[0-9a-f]+')

  if [ -z "$pcr0" ]; then
    echo "ERROR: Failed to extract PCR0 for ${enclave}" >&2
    return 1
  fi

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
