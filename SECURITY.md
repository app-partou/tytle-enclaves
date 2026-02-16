# Security Model

## Threat Model

### What the enclave protects against

1. **Host compromise**: Even if the EC2 host is fully compromised (root access), the attacker cannot:
   - Read or modify data inside the enclave memory
   - Forge NSM attestation documents (hardware-signed)
   - Intercept TLS traffic (TLS terminates inside the enclave)

2. **Man-in-the-middle**: The host cannot MITM API calls because:
   - TLS is negotiated end-to-end between the enclave and the remote server
   - The vsock-proxy is a blind TCP tunnel — it only sees encrypted bytes
   - The CA bundle is baked into the enclave image (part of PCR0)
   - `rejectUnauthorized: true` is hardcoded (not configurable)

3. **Code substitution**: An attacker cannot run different code while claiming the same attestation because:
   - PCR0 is a hash of the entire enclave image
   - Any code change = different PCR0
   - NSM hardware includes PCR0 in the signed attestation
   - Verifiers compare PCR0 against the public source build

### What the enclave does NOT protect against

1. **AWS itself**: AWS operates the Nitro hardware. In theory, AWS could produce fake attestations. This is mitigated by AWS's commercial reputation and the Nitro PKI being independently auditable.

2. **Denial of service**: The host can refuse to start the enclave, drop vsock packets, or shut down vsock-proxy. The system handles this with graceful fallback to unattested calls.

3. **Source code bugs**: If the enclave code has a bug (e.g., wrong URL allowlist), PCR0 will faithfully attest the buggy code. Code review and testing are the mitigations.

4. **Side channels**: Nitro Enclaves provide strong isolation but are not designed to resist all side-channel attacks (cache timing, etc.). This is acceptable for our threat model (API proxy, not key management).

## URL Allowlist

Each enclave service has a hardcoded URL allowlist. This is the primary isolation mechanism:

- **VIES enclave**: `ec.europa.eu`, `api.service.hmrc.gov.uk`
- **Future Stripe enclave**: `api.stripe.com`

Requests to any other host are rejected with HTTP 403. Since the allowlist is in the enclave source code, it's part of PCR0.

## Dependencies

### Supply chain

- Base images are pinned by digest (not tag)
- System packages are pinned by version
- npm dependencies are locked via `package-lock.json`
- Rust dependencies are pinned in `Cargo.toml` (`Cargo.lock` is generated during Docker build)

### Reproducibility

- `SOURCE_DATE_EPOCH` eliminates filesystem timestamp variation
- BuildKit `rewrite-timestamp=true` normalizes Docker layer timestamps
- Fixed UID (1000) avoids `/etc/passwd` differences

## Reporting

To report a security issue, email security@tytle.io.
