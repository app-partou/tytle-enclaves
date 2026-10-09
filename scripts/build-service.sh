#!/usr/bin/env bash
#
# Build one service's image with the one recipe of this repository (scripts/lib/recipe.sh), load it into Docker as
# tytle-enclave-<service>:<tag> and, given an ECR repository URI, push it as <uri>:<service>. The deploy runs it
# through each service's build.sh ("build.sh [tag] [ecr-uri]"). The same source gives the same image, and for an
# enclave the same PCR0.
#
# Usage: scripts/build-service.sh <service> [tag] [ecr-uri]
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib/recipe.sh
source "$REPO_DIR/scripts/lib/recipe.sh"

SERVICE="${1:-}"
IMAGE_TAG="${2:-latest}"
ECR_URI="${3:-}"
case "$SERVICE" in
  ''|*[!a-z-]*) echo "Usage: $0 <service> [tag] [ecr-uri]  (a service is a directory of this repository)" >&2; exit 2 ;;
esac
IMAGE="tytle-enclave-${SERVICE}:${IMAGE_TAG}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Building ${IMAGE} (the recipe: $(recipe_summary))"
recipe_build "$SERVICE" "$WORK/image.tar" "$IMAGE"
IMAGE_DIGEST="$(recipe_config_digest "$WORK/image.tar")"
docker load -i "$WORK/image.tar" >/dev/null
echo "Image built: ${IMAGE}"
echo "Image digest: ${IMAGE_DIGEST}"

if [ -n "$ECR_URI" ]; then
  docker tag "$IMAGE" "${ECR_URI}:${SERVICE}"
  docker push "${ECR_URI}:${SERVICE}"
  echo "Pushed to ${ECR_URI}:${SERVICE}"
fi
