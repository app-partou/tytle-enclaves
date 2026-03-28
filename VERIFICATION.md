# Verification Guide

How to independently verify that a Tytle enclave attestation is authentic.

## Overview

Every API call made through a Tytle enclave produces an NSM (Nitro Security Module) attestation document. This document contains:

- **PCR0**: Hash of the enclave image (code identity)
- **Nonce**: SHA-256(responseHash|apiEndpoint|timestamp) — ties the attestation to a specific response
- **COSE_Sign1 signature**: Signed by AWS Nitro hardware, verifiable against the Nitro root CA

Tytle runs three enclave services, each with its own PCR0:

| Service | Description |
|---------|-------------|
| `vies` | EU VAT number validation (VIES + HMRC) |
| `sicae` | Portuguese CAE code lookup |
| `stripe-payment` | Stripe payment data retrieval |

Because this repository is public, anyone can reproduce the build, compute the expected PCR0, and verify it matches the attestation. The current PCR0 and git commit for each service are published at:

```
GET https://api.tytle.io/api/enclave/pcr0
```

## Obtaining an Attestation Document

Every API call through a Tytle enclave produces an attestation document that is stored and publicly accessible. The verify endpoint returns both a server-side verification result and the full attestation document:

```
GET https://api.tytle.io/api/attestations/verify/:attestationId
```

To download the document for independent verification:

```bash
# If you have a claim verification token (from a share link):
ATTESTATION_ID=$(curl -s https://api.tytle.io/api/claims/verify/YOUR_TOKEN \
  | jq -r '.attestation.attestationId')

# Download the full attestation document (extract the 'document' field):
curl -s "https://api.tytle.io/api/attestations/verify/$ATTESTATION_ID" \
  | jq '.document' > attestation.json
```

Or directly if you know the attestation ID (e.g., `enc-550e8400-...`):

```bash
curl -s https://api.tytle.io/api/attestations/verify/enc-YOUR-ID \
  | jq '.document' > attestation.json
```

The attestation document contains only cryptographic hashes and public metadata — no PII or secrets.

## Quick Verification (CLI)

The easiest way to verify is with the `@tytle-enclaves/verify` CLI. It runs all checks end-to-end and outputs a full report:

```bash
# Full verification (cryptographic + reproducible build):
npx @tytle-enclaves/verify --service vies --attestation attestation.json

# Cryptographic verification only (no Docker required):
npx @tytle-enclaves/verify --service vies --attestation attestation.json --skip-build
```

Or as a single pipeline:

```bash
curl -s https://api.tytle.io/api/attestations/verify/enc-YOUR-ID \
  | jq '.document' \
  | npx @tytle-enclaves/verify --service vies --attestation -
```

This will:
1. Verify the COSE_Sign1 signature against the AWS Nitro root CA
2. Validate the certificate chain (expiry, key usage, basic constraints)
3. Verify the nonce binds the attestation to the specific response
4. Compare PCR0 against the published value from the API
5. Reproduce the Docker build from the exact source commit (unless `--skip-build`)
6. Extract PCR0 from the reproduced build (via nitro-cli in Docker)
7. Compare the reproduced PCR0 against the attestation
8. Output a final pass/fail report

## Manual Verification

The examples below use `vies` as the service. Replace `$SERVICE` with `sicae` or `stripe-payment` for other services — the steps are identical.

### Step 1: Fetch PCR0 and Commit Hash

Query the public endpoint to get the PCR0 and git commit currently deployed:

```bash
SERVICE=vies

curl -s https://api.tytle.io/api/enclave/pcr0 | jq ".enclaves.$SERVICE"
```

Response:

```json
{
  "pcr0": "abc123...",
  "gitCommit": "06c87ea...",
  "repoUrl": "https://github.com/app-partou/tytle-enclaves",
  "buildDir": "vies",
  "history": [
    { "pcr0": "abc123...", "gitCommit": "06c87ea...", "deployedAt": "2026-03-01T..." }
  ]
}
```

Save the values:

```bash
PCR0_EXPECTED=$(curl -s https://api.tytle.io/api/enclave/pcr0 | jq -r ".enclaves.$SERVICE.pcr0")
COMMIT=$(curl -s https://api.tytle.io/api/enclave/pcr0 | jq -r ".enclaves.$SERVICE.gitCommit")
```

### Step 2: Clone and Checkout the Exact Commit

Check out the specific commit that produced the deployed PCR0 — not the latest:

```bash
git clone https://github.com/app-partou/tytle-enclaves.git
cd tytle-enclaves
git checkout "$COMMIT"
```

### Step 3: Reproduce the Build

Build the enclave Docker image with deterministic timestamps:

```bash
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
docker buildx build \
  --output type=docker,rewrite-timestamp=true \
  --platform linux/amd64 \
  -t "verify-$SERVICE:latest" \
  -f "$SERVICE/Dockerfile" .
```

### Step 4: Compute and Compare PCR0

Convert the Docker image to an EIF (Enclave Image Format) and extract PCR0. This uses `nitro-cli`, which only runs on Amazon Linux — but you can run it inside Docker on any machine:

```bash
# Build a portable nitro-cli container (one-time)
docker build -t nitro-cli-helper - <<'EOF'
FROM amazonlinux:2023
RUN dnf install -y aws-nitro-enclaves-cli && dnf clean all
ENTRYPOINT ["nitro-cli"]
EOF

# Convert Docker image to EIF and extract PCR0
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  nitro-cli-helper build-enclave \
    --docker-uri "verify-$SERVICE:latest" \
    --output-file /tmp/verify.eif 2>&1 \
  | grep -o '"PCR0": "[^"]*"'
```

Compare the output PCR0 against the expected value from Step 1:

```
Your PCR0:        abc123...
Expected PCR0:    abc123...  <- must match
```

### Step 5: Verify the COSE_Sign1 Signature

The `nsmDocument` field in the attestation is a Base64-encoded COSE_Sign1 structure, signed by the Nitro Enclave's hardware key chain. To verify:

1. Decode the Base64 `nsmDocument`
2. Parse as CBOR — it's a COSE_Sign1: `[protected, unprotected, payload, signature]`
3. Build the Sig_structure: `["Signature1", protected, b"", payload]`
4. Extract the leaf certificate from the payload's `certificate` field
5. Verify the ECDSA P-384 (ES384) signature over the CBOR-encoded Sig_structure
6. Extract the `cabundle` (certificate chain) from the payload
7. Verify the chain from leaf → intermediates → root
8. Verify the root matches the [AWS Nitro Attestation PKI root CA](https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip)

### Step 6: Verify the Nonce

The nonce ties the attestation to a specific response:

```
nonce = SHA-256(responseHash|apiEndpoint|timestamp)
```

Where:
- `responseHash` = SHA-256 of the raw HTTP response body (hex string)
- `apiEndpoint` = hostname + path (e.g., `ec.europa.eu/taxation_customs/vies/services/checkVatService`)
- `timestamp` = Unix seconds when the attestation was created (number)
- `|` = literal pipe delimiter

Example:

```
responseHash = "a1b2c3..."
apiEndpoint  = "ec.europa.eu/taxation_customs/vies/services/checkVatService"
timestamp    = 1711612200

nonce = SHA-256("a1b2c3...|ec.europa.eu/taxation_customs/vies/services/checkVatService|1711612200")
```

Recompute the nonce from the attestation fields and verify it matches the `nonce` field.

## Why This Works

1. **PCR0 is deterministic**: Same source code + same base images + same dependencies = same PCR0
2. **PCR0 is in the attestation**: The NSM hardware includes PCR0 in the signed attestation document
3. **The signature is unforgeable**: Only AWS Nitro hardware can produce valid COSE_Sign1 signatures that chain to the Nitro root CA
4. **The nonce is bound**: The nonce commits the attestation to a specific API response

Together, this proves: "This specific response came from this specific code running in genuine Nitro hardware."

## PCR0 Drift

Any change to the enclave code, dependencies, or base image produces a new PCR0. When we update an enclave:

1. The new PCR0 is recorded and published via the public API: `GET https://api.tytle.io/api/enclave/pcr0`
2. The `history` array in the API response contains all previous PCR0 values with their git commits and deployment timestamps
3. Previous attestations remain valid against their respective PCR0 values — use the `history` array to find the matching entry

## Tools

For automated verification, use the CLI:

```bash
npx @tytle-enclaves/verify --service vies --attestation attestation.json
```

For programmatic verification in other languages, use any COSE/CBOR library:

- Python: `pycose`, `cbor2`
- JavaScript: `cose-js`, `cbor`
- Go: `go-cose`
- Rust: `coset`, `ciborium`

The AWS Nitro root certificate is available at:
https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
