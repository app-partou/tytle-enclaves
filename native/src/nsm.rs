use napi::bindgen_prelude::*;
use napi_derive::napi;

/// NSM (Nitro Security Module) ioctl command.
/// Computed as _IOWR(0x0A, 0, sizeof(NsmMessage)) on x86_64:
///   direction = 3 (read/write) << 30  = 0xC000_0000
///   size      = 32             << 16  = 0x0020_0000  (2 × iovec = 32 bytes)
///   type      = 0x0A           << 8   = 0x0000_0A00
///   nr        = 0              << 0   = 0x0000_0000
/// Reference: aws-nitro-enclaves-nsm-api/src/driver/mod.rs (NSM_IOCTL_MAGIC = 0x0A)
const NSM_IOCTL_CMD: u64 = 0xC020_0A00;

/// NSM message structure for ioctl.
/// Contains request and response iovec pointers.
#[repr(C)]
struct NsmMessage {
    request: libc::iovec,
    response: libc::iovec,
}

/// Send a raw CBOR-encoded NSM request and return the raw CBOR response.
///
/// The request should be CBOR-encoded (e.g., `{"Attestation": {"nonce": <bytes>, ...}}`).
/// Returns the raw CBOR response bytes from the NSM.
///
/// Only works inside a Nitro Enclave where /dev/nsm exists.
/// Outside an enclave, returns an error (use for graceful detection).
#[napi]
pub fn nsm_request(request: Buffer) -> Result<Buffer> {
    unsafe {
        // Open /dev/nsm
        let path = std::ffi::CString::new("/dev/nsm").unwrap();
        let fd = libc::open(path.as_ptr(), libc::O_RDWR);
        if fd < 0 {
            return Err(Error::from_reason(format!(
                "/dev/nsm open failed (not in enclave?): {}",
                std::io::Error::last_os_error()
            )));
        }

        // Allocate response buffer (NSM responses are typically < 16KB)
        let mut response_buf = vec![0u8; 16384];

        let mut msg = NsmMessage {
            request: libc::iovec {
                iov_base: request.as_ptr() as *mut libc::c_void,
                iov_len: request.len(),
            },
            response: libc::iovec {
                iov_base: response_buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: response_buf.len(),
            },
        };

        // ioctl call to NSM
        let ret = libc::ioctl(fd, NSM_IOCTL_CMD, &mut msg as *mut NsmMessage);
        libc::close(fd);

        if ret < 0 {
            return Err(Error::from_reason(format!(
                "NSM ioctl failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Truncate response buffer to actual response length
        response_buf.truncate(msg.response.iov_len);
        Ok(Buffer::from(response_buf))
    }
}
