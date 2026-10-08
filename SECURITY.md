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
   - The trusted roots are Node.js's bundled Mozilla CA store (`tls.rootCertificates`, compiled into the node binary of the digest-pinned image, so part of PCR0); the Alpine ca-certificates bundle is not used, and no `ca` option overrides the store. A bump of the Node image digest is a bump of the CA store: every upstream host is re-checked then (2026-10-08, Node 22.23.3: 119 roots; all five TLS upstreams verify)
   - `rejectUnauthorized: true` is hardcoded (not configurable)

3. **Code substitution**: An attacker cannot run different code while claiming the same attestation because:
   - PCR0 is a hash of the entire enclave image
   - Any code change = different PCR0
   - NSM hardware includes PCR0 in the signed attestation
   - Verifiers compare PCR0 against the public source build

4. **Someone else running the same code** (once Tytle runs signed EIFs): see Operator Binding below.

### What the enclave does NOT protect against

1. **AWS itself**: AWS operates the Nitro hardware. In theory, AWS could produce fake attestations. This is mitigated by AWS's commercial reputation and the Nitro PKI being independently auditable.

2. **Denial of service**: The host can refuse to start the enclave, drop vsock packets, or shut down vsock-proxy. The system handles this with graceful fallback to unattested calls.

3. **Source code bugs**: If the enclave code has a bug (e.g., wrong URL allowlist), PCR0 will faithfully attest the buggy code. Code review and testing are the mitigations.

4. **Side channels**: Nitro Enclaves provide strong isolation but are not designed to resist all side-channel attacks (cache timing, etc.). This is acceptable for our threat model: an API proxy whose one secret is a provider key sealed to it (Sealed Secrets below), which the host can already make the enclave use, but only for its handler's calls.

## Operator Binding

PCR0 says which code ran, not who ran it: this repository is public, so anyone can build the same EIF and run it in their own AWS account, and their attestation documents carry the same PCR0. Tytle signs the EIFs it runs (`scripts/build-eif.sh` with `EIF_SIGNING_KEY` and `EIF_SIGNING_CERT`). A signed EIF boots with PCR8 = SHA-384(48 zero bytes || SHA-384(the certificate's DER)); signing changes no other PCR, so a third party still rebuilds the unsigned EIF and compares PCR0, PCR1 and PCR2, and compares PCR8 with the published certificate (VERIFICATION.md, Step 9).

- The signing certificate is EC P-384 and self-signed. Its key is never in this repository, and it is meant to stay off the enclave host too: the deploy signs the EIF where it builds it, and the host only downloads and runs the EIF.
- An EIF whose certificate has expired does not start (`nitro-cli run-enclave` fails with E36, E39 and E11), so every restart of it would fail too. The build refuses a certificate with fewer than 60 days left.
- A new certificate changes PCR8 only. While one replaces another, a verifier accepts both PCR8s.
- Until Tytle runs signed EIFs, PCR8 is all zeroes.

## Sealed Secrets

A provider key (Stripe's platform key) reaches the enclave without crossing the host in clear (`shared/src/sealedSecret.ts`):

1. The deploy role encrypts the key once with the KMS key `alias/tytle-<env>-enclave-secrets` and the encryption context `enclave=<name>` (`stripe_payment`). A caller sends only that ciphertext (`sealedApiKey`). Seal the key's exact bytes: a trailing newline makes it a value the enclave refuses.
2. To open it, the enclave makes an RSA-2048 key pair in its own memory (once per process), asks the NSM for an attestation document that carries the public key and nothing else, and calls KMS `Decrypt` with that document as the `Recipient` (`RSAES_OAEP_SHA_256`). KMS answers with the key encrypted to that public key (`CiphertextForRecipient`, CMS EnvelopedData: RSAES-OAEP SHA-256, then AES-256-CBC), which only the enclave's private key opens. An answer that carries a `Plaintext` is refused.
3. The call is signed (SigV4) with the host role's temporary credentials, which the parent sends with each request for such an enclave, and it goes through the host's vsock-proxy for KMS (vsock port 8000, `kms.eu-central-1.amazonaws.com:443`), TLS end to end. Only an enclave whose own allowlist names KMS can make it: the Stripe Payment enclave.
4. The key policy grants the host role `kms:Decrypt` only with `kms:RecipientAttestation:ImageSha384` equal to the PCR0 of a named image of that enclave (the current one, and the previous one during a rotation) and with that enclave's encryption context. Without a `Recipient`, the condition key is absent, so a plain `Decrypt` by the host role is refused. The key and its policy are made outside this repository.

What this gives: the key is never in clear on the host, in data-bridge, in the parent or in a log. A compromised host can still send requests that make the enclave use the key, but only for the handler's own read-only Stripe calls: it cannot take the key and use it for anything else. Another image (a changed enclave, or one the policy no longer names) gets no `Decrypt`; a new release opens the key only after the policy names its PCR0. An opened key is kept in the enclave's memory for at most an hour; a refusal is never kept.

What it does not give: until every caller sends the sealed key, `apiKey` (the key in clear) is still accepted.

## URL Allowlist

Each enclave service has a hardcoded URL allowlist. This is the primary isolation mechanism:

- **VIES enclave**: `ec.europa.eu`, `api.service.hmrc.gov.uk`
- **Stripe Payment enclave**: `api.stripe.com`, and `kms.eu-central-1.amazonaws.com` for the one `Decrypt` above (Sealed Secrets)

Requests to any other host are rejected with HTTP 403. Since the allowlist is in the enclave source code, it's part of PCR0. An enclave whose allowlist does not name KMS cannot open a sealed secret.

## Dependencies

### Supply chain

- Base images are pinned by digest (not tag)
- System packages are pinned by version
- npm dependencies are locked via `package-lock.json`
- Rust dependencies are locked via the committed `Cargo.lock`: the build fails when it does not match `Cargo.toml` (`cargo fetch --locked`)

### Reproducibility

- ONE recipe builds every image (`scripts/lib/recipe.sh`, values in `scripts/build-recipe.json`): linux/amd64, and a BuildKit pinned by digest, run as its own builder
- A fixed `SOURCE_DATE_EPOCH` and BuildKit `rewrite-timestamp=true` give every new file the same time: an image, and its PCR0, changes only when what goes into it changes
- `scripts/expected-digests.json` records each enclave's image config digest and PCR0; CI builds every enclave twice on each pull request and fails unless both builds are that record
- `scripts/build-eif.sh` writes an EIF, signed or not, only when its build is that record
- Fixed UID (1000) avoids `/etc/passwd` differences

## Reporting

To report a security issue, email security@tytle.io.
