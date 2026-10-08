#!/usr/bin/env bash
#
# CI: the Rust addon's tests and lints (enclave audit P2.2; .github/workflows/ci.yml), on the toolchain of
# native/rust-toolchain.toml and the committed Cargo.lock. The vsock tests that need a Nitro host are #[ignore]d; the
# others, the socket deadlines among them, run on any Linux host.
#
set -euo pipefail

cd "$(dirname "$0")/../../native"
rustup component add clippy
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
