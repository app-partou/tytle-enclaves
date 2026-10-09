# tytle-enclaves

Public, auditable source code for Tytle's AWS Nitro Enclave applications.

Each service directory contains a thin config that defines which API hosts the enclave is allowed to call. The generic enclave infrastructure lives in `shared/`. Each service builds to its own EIF (Enclave Image Format) with its own PCR0 — the cryptographic hash that proves exactly which code (including the allowlist) is running inside the hardware-isolated enclave.

## Architecture

```
Fargate (data-bridge)
    |  POST /attest/fetch {id, url, method, headers, body, challenge}   (JSON, at most 64 KB)
    |  GET /health -> {healthy, enclaves, proxies}                     (503 when an enclave does not answer)
    |  Authorization: Bearer <ENCLAVE_PARENT_AUTH_TOKEN>                (when the parent has one; not on /health)
    v
Parent Server (EC2 host, port 5001)     <- generic router
    |  vsock (CID 16, port 5000)
    |  + the host role's AWS credentials (IMDSv2), only to an enclave that opens sealed secrets (Stripe)
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
shared/              Generic attested HTTP/HTTPS fetch (enclave core, manifest framework)
native/              Shared Rust napi-rs addon (vsock + NSM ioctl)
parent/              Generic parent server (routes requests to enclaves)
vies/                VIES/HMRC VAT validation enclave
sicae/               SICAE Portuguese business CAE code lookup enclave
stripe-payment/      Stripe payment data retrieval enclave
monerium-payment/    Monerium order + EURe balance enclave (Gnosis chain)
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

Copy `vies/Dockerfile` as a starting point, update paths from `vies/` to your service name. Then add the service to every per-service list - the verify CLI's `VALID_SERVICES`, `scripts/rotate-pcr0.sh` and `scripts/test-determinism.sh`; `verify/src/__tests__/services.drift.test.ts` fails until each names it.

### HTTP-Only Hosts

Set `tls: false` on an `AllowedHost` to skip TLS and send plain HTTP over the vsock tunnel. Without TLS, the EC2 host can read and modify traffic in transit. The NSM attestation still proves which code ran, but cannot guarantee response integrity. Only use for public, non-sensitive data (e.g., SICAE business CAE codes).

## Per-Service Isolation

| Property | VIES | SICAE | Stripe Payment | Monerium Payment |
|----------|------|-------|----------------|------------------|
| CID | 16 | 17 | 18 | 19 |
| ECR tag | `vies` | `sicae` | `stripe-payment` | `monerium-payment` |
| PCR0 SSM | `/tytle/{env}/enclave/vies/pcr0` | `/tytle/{env}/enclave/sicae/pcr0` | `/tytle/{env}/enclave/stripe_payment/pcr0` | `/tytle/{env}/enclave/monerium_payment/pcr0` |
| URL allowlist | `ec.europa.eu`, `api.service.hmrc.gov.uk` | `www.sicae.pt` | `api.stripe.com`, `kms.eu-central-1.amazonaws.com` (to open a sealed key: SECURITY.md, Sealed Secrets) | `api.monerium.app`, `rpc.gnosischain.com` |
| Transport | HTTPS (TLS) | HTTP (plain) | HTTPS (TLS) | HTTPS (TLS) |
| vsock-proxy ports | 8443, 8444 | 8445 | 8446, 8000 | 8447, 8448 |

Each enclave image contains ONLY shared core + its service config. PCR0 proves exactly which code ran. A VIES attestation's PCR0 can only match the VIES enclave image.

## Building

Every image is built by ONE recipe, `scripts/lib/recipe.sh`, with the values of `scripts/build-recipe.json`: linux/amd64; a fixed `SOURCE_DATE_EPOCH=1767225600` (2026-01-01T00:00:00Z), so an image - and its PCR0 - changes only when what goes into it changes; and BuildKit `moby/buildkit:v0.27.1@sha256:1e110c71d389d6d24f67b9438e2f7b8da749a6ff407b22a1631e025c95599368`, run as its own docker-container builder. The image goes to a docker tarball (`type=docker,dest=...,rewrite-timestamp=true`) and is then loaded into Docker.

```bash
cd vies && ./build.sh [tag] [ecr-uri]                    # each service: vies, sicae, stripe-payment, monerium-payment, parent
./scripts/test-determinism.sh [service]                  # build twice, compare, check scripts/expected-digests.json
./scripts/test-determinism.sh --update [service]         # record a meant change, then commit the file
./scripts/rotate-pcr0.sh <service|all>                   # the PCR0 of a build and the published one
./scripts/build-eif.sh <enclave> <out-dir>               # its EIF + measurements, written only if it is the record
EIF_SIGNING_KEY=key.pem EIF_SIGNING_CERT=cert.pem \
  ./scripts/build-eif.sh <enclave> <out-dir>             # the same EIF, signed: it adds PCR8
```

The scripts need Docker with buildx, and Node.js (the recipe reads its values with it). The verify CLI rebuilds with the same values (`verify/src/lib/buildRecipe.ts`).

A signed EIF carries PCR8, its signing certificate's, and every other PCR of the unsigned build (SECURITY.md, Operator Binding). The certificate must be EC P-384, the key's own, and valid for 60 more days at least: an EIF whose certificate has expired does not start. CI signs each enclave's EIF with a throwaway certificate on every pull request (`scripts/ci/test-signing.sh`).

## Handler Manifests

See [MANIFESTS.md](MANIFESTS.md) for the manifest framework — canonical query definitions, field-level provenance, composable policies, and repeatability guarantees.

## Verification

See [VERIFICATION.md](VERIFICATION.md) for how to reproduce PCR0 and verify attestations: who gets which attestation document, and which checks each allows. The `verify/` CLI runs every check end to end; it is not on npm yet, so build it from `verify/` (`npm ci && npm run build`, then `node dist/cli.js`).

## Security

See [SECURITY.md](SECURITY.md) for the threat model.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
