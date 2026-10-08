# Verifier test fixtures

`nitro-cli-1.4.4-build-enclave.stdout.txt` is the standard output of a real `nitro-cli build-enclave` (1.4.4, the pinned helper of `verify/Dockerfile.nitro-cli`, run for linux/amd64 on 2026-10-08): ONE JSON object over several lines. Its progress lines go to standard error. The image it measured was a VIES build of an earlier commit; the file tests the parser, not a PCR0.

The two folders are byte-for-byte copies of the Tytle main repository's verifier fixtures (`packages/attestation-core/src/__tests__/fixtures/`), so this CLI and the server-side verifier are tested on the same documents.

- `synthetic-chain/`: certificate chains in the AWS Nitro shape (root first in the cabundle, a 3-hour leaf, AWS's four-CA depth), made once by `generate.sh` and committed. They are trusted NOWHERE: the CLI pins the embedded AWS Nitro root (`src/lib/trustAnchor.ts`), and these chains verify only when a test swaps that one module for the synthetic root. The `*-TESTONLY.key.pem` files are the leaf keys the tests sign documents with; the CA keys were deleted after signing. `generate.sh` names the main repository's paths in its comments.
- `third-party/`: two REAL AWS Nitro attestation documents another project published as test data (Apache License 2.0; see its README). They verify under the embedded AWS root: the signature and the chain are AWS's. Their nonce and `user_data` follow that project's rules, so the Tytle bindings fail on them by construction.

Tytle's own captured documents (`real-*.json`, from the capture of gate G3) go next to these; the suite that reads them is skipped until they exist.
