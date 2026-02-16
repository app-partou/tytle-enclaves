# Verification Guide

How to independently verify that a Tytle enclave attestation is authentic.

## Overview

Every API call made through a Tytle enclave produces an NSM (Nitro Security Module) attestation document. This document contains:

- **PCR0**: Hash of the enclave image (code identity)
- **Nonce**: SHA-256(responseHash + apiEndpoint + timestamp) — ties the attestation to a specific response
- **COSE_Sign1 signature**: Signed by AWS Nitro hardware, verifiable against the Nitro root CA

Because this repository is public, anyone can reproduce the build, compute the expected PCR0, and verify it matches the attestation.

## Step 1: Reproduce the Build

Clone the repo and build the enclave image with deterministic timestamps:

```bash
git clone https://github.com/app-partou/tytle-enclaves.git
cd tytle-enclaves

# Build with SOURCE_DATE_EPOCH for reproducibility
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
docker buildx build \
  --output type=docker,rewrite-timestamp=true \
  --platform linux/amd64 \
  -t verify-vies:latest \
  -f vies/Dockerfile .
```

## Step 2: Compute PCR0

Convert the Docker image to an EIF and extract PCR0:

```bash
# Requires nitro-cli (install via aws-nitro-enclaves-cli)
nitro-cli build-enclave \
  --docker-uri verify-vies:latest \
  --output-file verify-vies.eif

# Extract PCR0
nitro-cli describe-eif --eif-path verify-vies.eif
# Output: { "Measurements": { "PCR0": "abc123...", ... } }
```

## Step 3: Compare with Attestation

The PCR0 from your local build should match the PCR0 in the NSM attestation document from the `enclave_attestations` table.

```
Your PCR0:        abc123...
Attestation PCR0: abc123...  <- must match
```

If they match, the attestation proves that the exact code in this repository processed the API call.

## Step 4: Verify the COSE_Sign1 Signature

The `nsm_document` field in the attestation is a Base64-encoded COSE_Sign1 structure, signed by the Nitro Enclave's hardware key chain. To verify:

1. Decode the Base64 `nsm_document`
2. Parse as CBOR — it's a COSE_Sign1: `[protected, unprotected, payload, signature]`
3. Extract the certificate chain from `protected` headers
4. Verify the signature against the payload using the leaf certificate
5. Verify the certificate chain roots to the [AWS Nitro Attestation PKI root](https://aws.amazon.com/ec2/nitro/nitro-enclaves/resources/)

## Step 5: Verify the Nonce

The nonce ties the attestation to a specific response:

```
nonce = SHA-256(responseHash + apiEndpoint + timestamp)
```

Where:
- `responseHash` = SHA-256 of the raw HTTP response body
- `apiEndpoint` = hostname + path (e.g., `ec.europa.eu/taxation_customs/vies/services/checkVatService`)
- `timestamp` = Unix seconds when the attestation was created

Recompute the nonce from the attestation fields and verify it matches.

## Why This Works

1. **PCR0 is deterministic**: Same source code + same base images + same dependencies = same PCR0
2. **PCR0 is in the attestation**: The NSM hardware includes PCR0 in the signed attestation document
3. **The signature is unforgeable**: Only AWS Nitro hardware can produce valid COSE_Sign1 signatures that chain to the Nitro root CA
4. **The nonce is bound**: The nonce commits the attestation to a specific API response

Together, this proves: "This specific response came from this specific code running in genuine Nitro hardware."

## PCR0 Drift

Any change to the enclave code, dependencies, or base image produces a new PCR0. When we update the enclave:

1. The new PCR0 is published in the release notes
2. The new PCR0 is stored in AWS SSM: `/tytle/{env}/enclave/vies/pcr0`
3. Previous attestations remain valid against their respective PCR0 values

## Tools

For programmatic verification, use the AWS Nitro Enclaves SDK or any COSE/CBOR library:

- Python: `pycose`, `cbor2`
- JavaScript: `cose-js`, `cbor`
- Go: `go-cose`
- Rust: `coset`, `ciborium`

The AWS Nitro root certificate is available at:
https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
