#!/bin/bash
# The Stripe Payment enclave image: built with the one recipe of this repository, loaded into Docker, and
# pushed as <ecr-uri>:stripe-payment when an ECR repository URI is given. See scripts/build-service.sh, scripts/lib/recipe.sh.
# Usage: ./build.sh [tag] [ecr-uri]
exec bash "$(cd "$(dirname "$0")/.." && pwd)/scripts/build-service.sh" stripe-payment "$@"
