#!/usr/bin/env bash
#
# How the EIF signing fixtures were made (enclave audit P1.6): once, on 2026-10-08, with OpenSSL 3.6, and committed.
# Every key here is TEST ONLY and trusted nowhere. Running this again makes NEW keys: then measure the nitro-cli pair
# again (below), because nitro-cli-1.4.4-signed.stdout.txt is bound to signer.pem.
#
# The real signing certificate has the shape of signer.pem (EC P-384, self-signed, two years). It lives in AWS Secrets
# Manager (gate G7), never in this repository.
set -euo pipefail
cd "$(dirname "$0")"
subject() { echo "/CN=tytle-probe-$1-TESTONLY"; }

# The signer
openssl ecparam -name secp384r1 -genkey -noout -out signer-TESTONLY.key.pem
openssl req -new -x509 -sha384 -key signer-TESTONLY.key.pem -out signer.pem -days 730 -subj "$(subject enclave-signer)"
# The same key, valid until 9999 (RFC 5280's "no expiry"): for the tests that run the check on today's clock
openssl req -new -x509 -sha384 -key signer-TESTONLY.key.pem -out signer-long-lived.pem \
  -not_before 20261008000000Z -not_after 99991231235959Z -subj "$(subject enclave-signer-long-lived)"

# One refusal of scripts/lib/recipe.mjs signingCheck each
openssl ecparam -name secp384r1 -genkey -noout -out other-TESTONLY.key.pem     # a key that is not the certificate's
openssl ecparam -name prime256v1 -genkey -noout -out p256-TESTONLY.key.pem     # P-256, not P-384
openssl req -new -x509 -sha256 -key p256-TESTONLY.key.pem -out p256.pem -days 730 -subj "$(subject p256)"
openssl req -new -x509 -sha384 -key signer-TESTONLY.key.pem -out ends-in-30-days.pem -days 30 \
  -subj "$(subject ends-in-30-days)"
openssl req -new -x509 -sha384 -key signer-TESTONLY.key.pem -out expired.pem \
  -not_before 20240101000000Z -not_after 20250101000000Z -subj "$(subject expired)"
openssl req -new -x509 -sha384 -key signer-TESTONLY.key.pem -out not-yet-valid.pem \
  -not_before 20300101000000Z -not_after 20320101000000Z -subj "$(subject future)"

# The nitro-cli pair: ONE image (vies at the release, config sha256:b86896b1...; measured again whenever the vies entry of
# scripts/expected-digests.json changes - buildEif.test.ts says so) measured by the pinned helper
# (verify/Dockerfile.nitro-cli, run for linux/amd64), first unsigned, then signed with signer.pem. Its standard
# output only (the progress lines go to standard error):
#   docker run --rm --platform linux/amd64 -v /var/run/docker.sock:/var/run/docker.sock <helper> build-enclave \
#     --docker-uri <image> --output-file /tmp/unsigned.eif > nitro-cli-1.4.4-unsigned.stdout.txt
#   docker run --rm --platform linux/amd64 -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/keys:ro" <helper> \
#     build-enclave --docker-uri <image> --output-file /tmp/signed.eif \
#     --private-key /keys/signer-TESTONLY.key.pem --signing-certificate /keys/signer.pem \
#     > nitro-cli-1.4.4-signed.stdout.txt
# scripts/build-eif.sh runs the same two commands through scripts/lib/recipe.sh (recipe_measure).
