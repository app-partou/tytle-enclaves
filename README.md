# tytle-enclaves

Public, auditable source code for Tytle's AWS Nitro Enclave applications.

Each service directory contains a thin config that defines which API hosts the enclave is allowed to call. The generic enclave infrastructure lives in `shared/`. Each service builds to its own EIF (Enclave Image Format) with its own PCR0 — the cryptographic hash that proves exactly which code (including the allowlist) is running inside the hardware-isolated enclave.

## Architecture

```
Fargate (ai-agent-server)
    |  POST /attest/fetch {url, method, headers, body}
    v
Parent Server (EC2 host, port 5001)     <- generic router
    |  vsock (CID 16, port 5000)
    v
Nitro Enclave                            <- this repo
    |  1. Validate URL against allowlist
    |  2. vsock to CID 3:port -> vsock-proxy -> remote:443
    |  3. TLS handshake inside enclave (host can't MITM)
    |  4. HTTP request/response
    |  5. SHA-256 hash response
    |  6. NSM attestation via /dev/nsm ioctl
    v
Response + {nsmDocument, pcrs, nonce, ...}
```

## Directory Structure

```
shared/          Generic attested HTTP/HTTPS fetch (enclave core)
native/          Shared Rust napi-rs addon (vsock + NSM ioctl)
parent/          Generic parent server (routes requests to enclaves)
vies/            VIES/HMRC VAT validation enclave (config only)
sicae/           SICAE Portuguese business CAE code lookup enclave (config only)
```

### Adding a New Enclave Service

Each service is just a config file + Dockerfile. See `sicae/` for a complete example, including HTTP-only (no TLS) support via `tls: false`:

```typescript
// sicae/src/enclave.ts
import { startEnclave } from '@tytle-enclaves/shared';

startEnclave({
  name: 'sicae',
  hosts: [
    { hostname: 'www.sicae.pt', vsockProxyPort: 8445, tls: false },
  ],
});
```

Copy `vies/Dockerfile` as a starting point, update paths from `vies/` to your service name.

### HTTP-Only Hosts

Set `tls: false` on an `AllowedHost` to skip TLS and send plain HTTP over the vsock tunnel. Without TLS, the EC2 host can read and modify traffic in transit. The NSM attestation still proves which code ran, but cannot guarantee response integrity. Only use for public, non-sensitive data (e.g., SICAE business CAE codes).

## Per-Service Isolation

| Property | VIES Enclave | SICAE Enclave | Future Stripe Enclave |
|----------|-------------|---------------|----------------------|
| CID | 16 | 17 | 18 |
| ECR tag | `vies` | `sicae` | `stripe` |
| PCR0 SSM | `/tytle/{env}/enclave/vies/pcr0` | `/tytle/{env}/enclave/sicae/pcr0` | `/tytle/{env}/enclave/stripe/pcr0` |
| URL allowlist | `ec.europa.eu`, `api.service.hmrc.gov.uk` | `www.sicae.pt` | `api.stripe.com` |
| Transport | HTTPS (TLS) | HTTP (plain) | HTTPS (TLS) |
| vsock-proxy ports | 8443, 8444 | 8445 | 8446 |

Each enclave image contains ONLY shared core + its service config. PCR0 proves exactly which code ran. A VIES attestation's PCR0 can only match the VIES enclave image.

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

### SICAE Enclave

```bash
cd sicae
./build.sh [tag] [ecr-uri]
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
