# tytle-enclaves

Public, auditable source code for Tytle's AWS Nitro Enclave applications.

Each subdirectory contains the source for one enclave service. Each service has its own Dockerfile, builds to its own EIF (Enclave Image Format), and produces its own PCR0 — the cryptographic hash that proves exactly which code is running inside the hardware-isolated enclave.

## Architecture

```
Fargate (ai-agent-server)
    |  POST /attest/fetch {url, method, headers, body}
    v
Parent Server (EC2 host, port 5001)     <- generic router
    |  vsock (CID 16, port 5000)
    v
VIES Nitro Enclave                       <- this repo
    |  1. vsock to CID 3:8443 -> vsock-proxy -> ec.europa.eu:443
    |  2. TLS handshake inside enclave (host can't MITM)
    |  3. SOAP POST / REST GET
    |  4. SHA-256 hash response
    |  5. NSM attestation via /dev/nsm ioctl
    v
Response + {nsmDocument, pcrs, nonce, ...}
```

## Directory Structure

```
native/          Shared Rust napi-rs addon (vsock + NSM ioctl)
vies/            VIES/HMRC VAT validation enclave
parent/          Generic parent server (routes requests to enclaves)
```

## Per-Service Isolation

| Property | VIES Enclave | Future Stripe Enclave |
|----------|-------------|----------------------|
| CID | 16 | 17 |
| ECR tag | `vies` | `stripe` |
| PCR0 SSM | `/tytle/{env}/enclave/vies/pcr0` | `/tytle/{env}/enclave/stripe/pcr0` |
| URL allowlist | `ec.europa.eu`, `api.service.hmrc.gov.uk` | `api.stripe.com` |
| vsock-proxy ports | 8443, 8444 | 8445 |

Each enclave image contains ONLY its service's code. PCR0 proves exactly which code ran. A VIES attestation's PCR0 can only match the VIES enclave image.

## Building

### VIES Enclave

```bash
cd vies
./build.sh [tag] [ecr-uri]

# Or manually:
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) \
docker buildx build \
  --output type=docker,rewrite-timestamp=true \
  --platform linux/amd64 \
  -t tytle-enclave-vies:latest \
  -f Dockerfile ..
```

### Parent Server

```bash
cd parent
docker build -t tytle-enclave-parent:latest .
```

## Verification

See [VERIFICATION.md](VERIFICATION.md) for how to reproduce PCR0 and verify attestations.

## Security

See [SECURITY.md](SECURITY.md) for the threat model.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
