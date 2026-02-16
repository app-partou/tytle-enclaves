#!/bin/bash
# Reproducible VIES enclave Docker image build.
# Uses SOURCE_DATE_EPOCH + BuildKit rewrite-timestamp for deterministic filesystem timestamps.
# Same source + same base digest = same image content hash = same PCR0 after nitro-cli build-enclave.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

IMAGE_TAG="${1:-latest}"
ECR_URI="${2:-}"
SOURCE_DATE_EPOCH=$(git -C "$REPO_DIR" log -1 --pretty=%ct)

export SOURCE_DATE_EPOCH

echo "Building VIES enclave image with SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

docker buildx build \
  --output type=docker,rewrite-timestamp=true \
  --platform linux/amd64 \
  -t "tytle-enclave-vies:${IMAGE_TAG}" \
  -f "${SCRIPT_DIR}/Dockerfile" \
  "$REPO_DIR"

IMAGE_DIGEST=$(docker inspect --format='{{.Id}}' "tytle-enclave-vies:${IMAGE_TAG}")
echo "Image built: tytle-enclave-vies:${IMAGE_TAG}"
echo "Image digest: ${IMAGE_DIGEST}"

if [ -n "$ECR_URI" ]; then
  docker tag "tytle-enclave-vies:${IMAGE_TAG}" "${ECR_URI}:vies"
  docker push "${ECR_URI}:vies"
  echo "Pushed to ${ECR_URI}:vies"
fi
