#!/bin/bash
# The parent server image (it runs on the host, not in an enclave: no PCR0, the same build): built with the one recipe
# of this repository, loaded into Docker, and pushed as <ecr-uri>:parent when an ECR repository URI is given.
# See scripts/build-service.sh, scripts/lib/recipe.sh.
# Usage: ./build.sh [tag] [ecr-uri]
exec bash "$(cd "$(dirname "$0")/.." && pwd)/scripts/build-service.sh" parent "$@"
