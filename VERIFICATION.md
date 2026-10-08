# Verification Guide

How to independently verify that a Tytle enclave attestation is authentic.

## Overview

Every API call made through a Tytle enclave produces an NSM (Nitro Security Module) attestation document. This document contains:

- **PCR0**: Hash of the enclave image (code identity)
- **Nonce**: SHA-256(responseHash|apiEndpoint|timestamp), with `|challenge` appended when the caller sent a challenge (version 2). It ties the attestation to a specific response (and, in version 2, to one request)
- **user_data**: SHA-256 of the BN254 vector the enclave encoded from the response, when the service encodes one: it ties the attestation to the data you receive
- **timestamp**: when the document was signed, stamped by the Nitro hypervisor
- **COSE_Sign1 signature**: Signed by AWS Nitro hardware, verifiable against the Nitro root CA

This repository builds four enclave services, each with its own PCR0:

| Service | Description |
|---------|-------------|
| `vies` | EU VAT number validation (VIES + HMRC) |
| `sicae` | Portuguese CAE code lookup |
| `stripe-payment` | Stripe payment data retrieval |
| `monerium-payment` | Monerium order + EURe on-chain balance |

Because this repository is public, anyone can reproduce the build, compute the expected PCR0, and verify it matches the attestation. The PCR0 and git commit of each service Tytle runs are published at:

```
GET https://api.tytle.io/api/enclave/pcr0
```

## Obtaining an Attestation Document

The verify endpoint returns the server's own verification result (`verification`) and the attestation document (`document`):

```
GET https://api.tytle.io/api/attestations/verify/:attestationId
```

What the document holds depends on who asks:

- **Anyone (no sign-in)**: the NSM material - `attestationId`, `responseHash`, `apiMethod`, `timestamp`, `nsmDocument`, `pcrs.pcr0`, `nonce`, `bn254Hash`, and `nonceVersion` + `challenge` for a version-2 document. `requestHash` and `apiEndpoint` are left out: they carry identifiers (the request carries the tax number looked up; an HMRC lookup path carries the GB VAT number).
- **A signed-in Tytle employee**: the full document, with `requestHash` and `apiEndpoint`.
- **A claim link** (`GET https://api.tytle.io/api/claims/verify/:token`): each attestation behind the claim with its `attestationId`, `apiEndpoint`, `responseHash`, PCR0, time and the server's verdict, but no NSM document.

Which checks each document allows:

| Check | Anonymous document | Full document |
|-------|--------------------|---------------|
| COSE_Sign1 signature and the AWS certificate chain | yes | yes |
| PCR0: published value, reproduced build, not a debug-mode enclave | yes | yes |
| user_data equals bn254Hash; the vector you received (`--bn254`) | yes | yes |
| Nonce recomputed from responseHash, apiEndpoint, timestamp (and challenge) | no: it needs `apiEndpoint` | yes |

The nonce recompute and the request binding wait for the subject re-key ("Phase 8"), which takes the identifiers out of those two fields; until then they need the full document. The CLI below recomputes the nonce, so it needs the full document: it refuses a document without `requestHash` and `apiEndpoint`. With the anonymous document, do the other checks by hand (Manual Verification, steps 1-5 and 7) or with any COSE library.

To download the document for independent verification (an employee's token gives the full document):

```bash
curl -s -H "Authorization: Bearer $JWT" \
  "https://api.tytle.io/api/attestations/verify/enc-YOUR-ID" \
  | jq '.document' > attestation.json
```

If you have a claim link, take the attestation ids from it:

```bash
curl -s https://api.tytle.io/api/claims/verify/YOUR_TOKEN | jq -r '.attestations[].attestationId'
```

## Quick Verification (CLI)

The `verify/` folder of this repository is a CLI that runs every check end to end and prints a report. It is not published on npm yet: build it from this repository (Node.js 20 or later):

```bash
git clone https://github.com/app-partou/tytle-enclaves.git
cd tytle-enclaves/verify
npm ci
npm run build

# Full verification (cryptographic + reproducible build; needs Docker):
node dist/cli.js --service vies --attestation attestation.json

# Cryptographic verification only (no Docker required):
node dist/cli.js --service vies --attestation attestation.json --skip-build

# Also check the BN254 vector you received (base64, in a file) is the one signed:
node dist/cli.js --service vies --attestation attestation.json --bn254 vector.b64
```

Or as a single pipeline:

```bash
curl -s -H "Authorization: Bearer $JWT" "https://api.tytle.io/api/attestations/verify/enc-YOUR-ID" \
  | jq '.document' \
  | node dist/cli.js --service vies --attestation -
```

This will:
1. Verify the COSE_Sign1 signature (ES384) with the leaf certificate in the document
2. Validate the certificate chain to the AWS Nitro root CA embedded in the CLI (pinned by fingerprint), judged at the signed time; refuse a debug-mode enclave (PCR0 all zeroes)
3. Recompute the nonce (version 1 or 2), check it is the nonce in the signed document (a document without one fails), and check the document's `timestamp` is within 10 minutes of the signed time
4. Check `user_data` equals `bn254Hash`; with `--bn254`, check the vector hashes to `bn254Hash` and, as base64, to `responseHash`
5. Compare PCR0 against the published value from the API (or `--pcr0`), searching the published history for older releases
6. Reproduce the Docker build from the published commit of https://github.com/app-partou/tytle-enclaves (unless `--skip-build`); the build never comes from a repository the API names
7. Extract PCR0 from the reproduced build with the pinned nitro-cli helper (`verify/Dockerfile.nitro-cli`)
8. Compare the reproduced PCR0 against the attestation
9. Output a final pass/fail report

## Manual Verification

The examples below use `vies` as the service. Replace `$SERVICE` with `sicae`, `stripe-payment` or `monerium-payment` for other services - the steps are identical.

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

The API key of a service is its name with `_` for `-` (`stripe_payment`, `monerium_payment`). Save the values:

```bash
PCR0_EXPECTED=$(curl -s https://api.tytle.io/api/enclave/pcr0 | jq -r ".enclaves.$SERVICE.pcr0")
COMMIT=$(curl -s https://api.tytle.io/api/enclave/pcr0 | jq -r ".enclaves.$SERVICE.gitCommit")
```

### Step 2: Clone and Checkout the Exact Commit

Check out the specific commit that produced the deployed PCR0, not the latest. Clone this repository, whatever `repoUrl` the API names:

```bash
git clone https://github.com/app-partou/tytle-enclaves.git
cd tytle-enclaves
git checkout "$COMMIT"
```

### Step 3: Reproduce the Build

Build the enclave image with the build recipe of the commit you checked out, `scripts/build-recipe.json`: linux/amd64 (what a Nitro host runs), a fixed file time (`SOURCE_DATE_EPOCH`, the same for every commit: an image changes only when what goes into it changes) and a BuildKit pinned by digest, run as its own builder. `scripts/lib/recipe.sh` builds every image of this repository with these values, and the verify CLI rebuilds with them. The image goes to a tarball, then into Docker: Docker's containerd image store (Docker Desktop's default) refuses `rewrite-timestamp` on a direct load.

```bash
# The pinned BuildKit, as its own builder (one-time)
docker buildx create --name tytle-repro --driver docker-container \
  --driver-opt image=moby/buildkit:v0.27.1@sha256:1e110c71d389d6d24f67b9438e2f7b8da749a6ff407b22a1631e025c95599368

SOURCE_DATE_EPOCH=1767225600 docker buildx build \
  --builder tytle-repro \
  --platform linux/amd64 \
  --provenance=false --sbom=false \
  --output "type=docker,dest=verify-$SERVICE.tar,rewrite-timestamp=true,name=verify-$SERVICE:latest" \
  -f "$SERVICE/Dockerfile" .

docker load -i "verify-$SERVICE.tar"
```

If the values in the commit's `scripts/build-recipe.json` differ from these, use the commit's. A commit without the file was built before the fixed recipe, with the time of its own commit.

### Step 4: Compute and Compare PCR0

Convert the Docker image to an EIF (Enclave Image Format) and extract PCR0. This uses `nitro-cli`, which only runs on Amazon Linux - but you can run it inside Docker on any machine. The `verify/Dockerfile.nitro-cli` in this repo pins the base image by digest and the nitro-cli version, so you get the same helper binary regardless of when you run it (the CLI builds its helper from the same file). Build and run it for linux/amd64 on every machine: on an arm64 machine (an Apple Silicon Mac) Docker picks the arm64 variant, and that nitro-cli cannot read an amd64 image (error E48).

```bash
# Build the portable nitro-cli helper container (one-time)
docker build --platform linux/amd64 -t nitro-cli-helper -f verify/Dockerfile.nitro-cli verify/

# Convert the image to an EIF; nitro-cli prints its measurements as one JSON object
docker run --rm --platform linux/amd64 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  nitro-cli-helper build-enclave \
    --docker-uri "verify-$SERVICE:latest" \
    --output-file /tmp/verify.eif \
  | jq -r .Measurements.PCR0
```

Compare the output PCR0 against the expected value from Step 1:

```
Your PCR0:        abc123...
Expected PCR0:    abc123...  <- must match
```

The commit's `scripts/expected-digests.json` records the same PCR0 (and the image's config digest) for each enclave: CI builds every enclave twice on each pull request and fails unless both builds are that record.

### Step 5: Verify the COSE_Sign1 Signature and the Certificate Chain

The `nsmDocument` field in the attestation is a Base64-encoded COSE_Sign1 structure, signed by the Nitro Enclave's hardware key chain. To verify:

1. Decode the Base64 `nsmDocument`
2. Parse as CBOR - it's a COSE_Sign1: `[protected, unprotected, payload, signature]`; the protected header's algorithm must be ES384 (`-35`)
3. Build the Sig_structure: `["Signature1", protected, b"", payload]`
4. Extract the leaf certificate from the payload's `certificate` field
5. Verify the ECDSA P-384 (ES384) signature over the CBOR-encoded Sig_structure
6. Extract the `cabundle` from the payload. AWS orders it root first: `[ROOT, INTERM_1, ..., INTERM_N]`
7. Verify the path leaf → INTERM_N → ... → INTERM_1 → ROOT: the leaf is signed by the last cabundle member, and each member by the one before it; every member is a CA, the leaf is not
8. Verify `cabundle[0]` IS the [AWS Nitro Attestation PKI root CA](https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip): its SHA-256 fingerprint is `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`
9. Judge every certificate's validity at the payload's `timestamp` (milliseconds; the signing time), not at "now": the leaf lives about three hours, and the lower CAs days. The root itself must be valid now
10. Check PCR0 in the payload's `pcrs` is not all zeroes: a debug-mode enclave measures zeroes, and its memory is readable from the host, so its document proves nothing

### Step 6: Verify the Nonce

The nonce ties the attestation to a specific response. The document says which version it signed (`nonceVersion`; absent means 1):

```
version 1: nonce = SHA-256(responseHash|apiEndpoint|timestamp)
version 2: nonce = SHA-256(responseHash|apiEndpoint|timestamp|challenge)
```

Where:
- `responseHash` = SHA-256 (hex) of the body the enclave returned: for a service that encodes a BN254 vector (the document has `bn254Hash`), the vector as base64 text; otherwise the raw HTTP response body
- `apiEndpoint` = hostname + path (e.g., `ec.europa.eu/taxation_customs/vies/services/checkVatService`)
- `timestamp` = the document's `timestamp` (Unix seconds). Since the 2026-10 enclave release it follows the hypervisor's clock, the same clock that signs the payload's `timestamp` (in milliseconds); it must be within 10 minutes of it
- `challenge` = the caller's challenge, 64 lowercase hex characters, echoed in the document (version 2 only)
- `|` = literal pipe delimiter

Example:

```
responseHash = "a1b2c3..."
apiEndpoint  = "ec.europa.eu/taxation_customs/vies/services/checkVatService"
timestamp    = 1711612200

nonce = SHA-256("a1b2c3...|ec.europa.eu/taxation_customs/vies/services/checkVatService|1711612200")
```

Recompute the nonce from the attestation fields and verify it matches the `nonce` field, and that the `nonce` field is the `nonce` in the signed payload. A payload without a nonce is not bound to the response.

### Step 7: Verify the Data Binding

When the service encodes a BN254 vector, the payload's `user_data` is SHA-256 of the vector's bytes, and the document's `bn254Hash` must equal it. If you received the vector (base64), check that SHA-256 of its decoded bytes is `bn254Hash` and that SHA-256 of the base64 text is `responseHash`. A document whose payload has `user_data` but no `bn254Hash`, or the other way round, fails.

### Step 8: Verify the Handler Manifest (Optional)

Services that declare a handler manifest include a `x-manifest-hash` in the attestation's request headers. This hash is a SHA-256 of the manifest JSON (with deterministically sorted keys), binding the attestation to a specific handler specification.

To verify:

1. Find the manifest hash in the response headers: `x-{service}-manifest-hash`
2. Read the handler's `manifest.ts` from the source commit checked out in Step 2
3. Compute `SHA-256(stableStringify(manifest))` where `stableStringify` sorts object keys recursively
4. Verify it matches the hash from step 1

The manifest describes every API query, every field derivation, and every validation policy. See [MANIFESTS.md](MANIFESTS.md) for the full specification.

## Why This Works

1. **PCR0 is deterministic**: Same source code + same base images + same dependencies = same PCR0
2. **PCR0 is in the attestation**: The NSM hardware includes PCR0 in the signed attestation document
3. **The signature is unforgeable**: Only AWS Nitro hardware can produce valid COSE_Sign1 signatures that chain to the Nitro root CA
4. **The nonce is bound**: The nonce commits the attestation to a specific API response (and, in version 2, to one request)
5. **The data is bound**: `user_data` commits the attestation to the BN254 vector you receive

Together, this proves: "This specific response came from this specific code running in genuine Nitro hardware."

## PCR0 Drift

Any change to the enclave code, dependencies, or base image produces a new PCR0. When we update an enclave:

1. The new PCR0 is recorded and published via the public API: `GET https://api.tytle.io/api/enclave/pcr0`
2. The `history` array in the API response contains all previous PCR0 values with their git commits and deployment timestamps
3. Previous attestations remain valid against their respective PCR0 values - use the `history` array to find the matching entry

## Tools

For automated verification, build and run the CLI (see Quick Verification):

```bash
node verify/dist/cli.js --service vies --attestation attestation.json
```

For programmatic verification in other languages, use any COSE/CBOR library:

- Python: `pycose`, `cbor2`
- JavaScript: `cose-js`, `cbor`
- Go: `go-cose`
- Rust: `coset`, `ciborium`

The AWS Nitro root certificate is available at:
https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
