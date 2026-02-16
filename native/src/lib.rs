//! Native addon for Nitro Enclave operations.
//!
//! Provides two modules:
//! - vsock: AF_VSOCK socket server/client for enclave ↔ host communication
//! - nsm: /dev/nsm ioctl for NSM attestation requests

mod nsm;
mod vsock;
