# Third-party AWS Nitro attestation documents (test data)

Real attestation documents that AWS Nitro Enclaves produced for ANOTHER project, which published them as test data. They let the verifier tests run the embedded AWS root against chains AWS really issued, before Tytle's own documents are captured (enclave audit 2026-10, P0.3 and P2.1). They are not Tytle documents: their nonce and `user_data` follow their own project's rules, so the two Tytle bindings (`nonce_verify`, `bn254_binding`) fail on them by construction.

| File | Upstream (pinned commit) | Licence | What it is |
|---|---|---|---|
| `automata-attestation-2.json` | [automata-network/aws-nitro-enclave-attestation `samples/attestation_2.report`](https://github.com/automata-network/aws-nitro-enclave-attestation/blob/bda8f0fb3ebdfdbba8a04e0759cba86a81d92074/samples/attestation_2.report) | [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) | ap-southeast-1, signed 2023-09-28T11:08:27.117Z; cabundle of four (root, regional, zonal, instance); a release-mode PCR0 |
| `automata-attestation-1.json` | [same repository, `samples/attestation_1.report`](https://github.com/automata-network/aws-nitro-enclave-attestation/blob/bda8f0fb3ebdfdbba8a04e0759cba86a81d92074/samples/attestation_1.report) | [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) | us-east-2, signed 2024-08-16T09:11:49.167Z; a DEBUG-MODE enclave (PCR0 all zeroes) |

Upstream NOTICE: "Copyright 2025 Automata. All Rights Reserved."

Each JSON holds the upstream file's bytes unchanged, base64-encoded, with their SHA-256 (the tests check it). Fetched 2026-10-07. The payloads carry no personal data: hashes, a nonce, and the strings "1234" and "Automata MPC Demo".
