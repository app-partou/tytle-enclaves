//! Native addon for Nitro Enclave operations.
//!
//! Provides two modules:
//! - vsock: AF_VSOCK socket server/client for enclave ↔ host communication
//! - nsm: /dev/nsm ioctl for NSM attestation requests

// `pub` so the #[napi] items and their task types count as used and public for the dead-code and
// private-interface lints (`cargo clippy -D warnings` in CI); the JS surface is the same.
pub mod nsm;
pub mod vsock;
