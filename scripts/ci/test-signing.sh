#!/usr/bin/env bash
#
# CI: one enclave's EIF signed as the deploy is to sign it, but with a throwaway certificate (enclave audit P1.6). The
# certificate and its key are made here, in the shape of the real one (EC P-384, self-signed, two years), and deleted
# after. scripts/build-eif.sh checks the certificate before the build, then that the signed EIF is the committed build
# (signing changes no PCR but PCR8) and that its PCR8 is the certificate's.
#
# Usage: scripts/ci/test-signing.sh <enclave>
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ENCLAVE="${1:?Usage: scripts/ci/test-signing.sh <enclave>}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

openssl ecparam -name secp384r1 -genkey -noout -out "$WORK/key.pem"
openssl req -new -x509 -sha384 -key "$WORK/key.pem" -out "$WORK/cert.pem" -days 730 \
  -subj "/CN=tytle-ci-throwaway-enclave-signer"

EIF_SIGNING_KEY="$WORK/key.pem" EIF_SIGNING_CERT="$WORK/cert.pem" \
  bash "$REPO_DIR/scripts/build-eif.sh" "$ENCLAVE" "$WORK/eif"
