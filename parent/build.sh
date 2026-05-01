#!/bin/bash
# Parent server Docker image build.
# Uses SOURCE_DATE_EPOCH + BuildKit rewrite-timestamp for consistency with enclave builds.
# The parent server is NOT an enclave (no PCR0), but we keep the same build hygiene.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

IMAGE_TAG="${1:-latest}"
ECR_URI="${2:-}"
SOURCE_DATE_EPOCH=$(git -C "$REPO_DIR" log -1 --pretty=%ct)

export SOURCE_DATE_EPOCH

echo "Building parent server image with SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

docker buildx build \
  --output type=docker,rewrite-timestamp=true \
  --platform linux/amd64 \
  -t "tytle-enclave-parent:${IMAGE_TAG}" \
  -f "${SCRIPT_DIR}/Dockerfile" \
  "$REPO_DIR"

IMAGE_DIGEST=$(docker inspect --format='{{.Id}}' "tytle-enclave-parent:${IMAGE_TAG}")
echo "Image built: tytle-enclave-parent:${IMAGE_TAG}"
echo "Image digest: ${IMAGE_DIGEST}"

if [ -n "$ECR_URI" ]; then
  docker tag "tytle-enclave-parent:${IMAGE_TAG}" "${ECR_URI}:parent"
  docker push "${ECR_URI}:parent"
  echo "Pushed to ${ECR_URI}:parent"
fi
