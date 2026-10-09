use napi::bindgen_prelude::*;
use napi::Task;
use napi_derive::napi;
use std::sync::atomic::{AtomicI32, Ordering};

/// AF_VSOCK constants — not in libc crate, defined by Linux kernel
const AF_VSOCK: i32 = 40;
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

/// Sentinel value indicating the fd has been closed.
const CLOSED_FD: i32 = -1;

/// Read/write timeout of a socket from `VsockStream::connect` when the caller gives none.
const DEFAULT_IO_TIMEOUT_SECS: u32 = 30;

/// Read/write timeout of an accepted connection. The parent writes its whole request at once and
/// reads the answer at once, so a peer that goes quiet for this long is gone or hostile. Every read
/// and write is a blocking libc call on the Node.js event loop: while one waits, the enclave serves
/// nothing else, so this bounds the longest freeze a peer can cause per call. The JS side adds a
/// deadline over the whole message (shared/src/protocol.ts), which bounds a peer that trickles bytes.
const ACCEPTED_IO_TIMEOUT_SECS: u32 = 10;

/// Set SO_RCVTIMEO and SO_SNDTIMEO on `fd`, so a blocking read or write returns EAGAIN after `secs`
/// instead of waiting forever (0 would mean "no timeout" to the kernel, so it is raised to 1).
///
/// # Safety
/// `fd` must be an open socket owned by the caller.
pub(crate) unsafe fn set_io_timeouts(fd: i32, secs: u32) -> std::io::Result<()> {
    let tv = libc::timeval {
        // `as _`: the field's own type. libc deprecates naming `time_t` on musl targets (rust-lang/libc#1848), the
        // enclave's target; the type itself is 64-bit on x86_64 either way.
        tv_sec: secs.max(1) as _,
        tv_usec: 0,
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        let ret = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Give a freshly accepted connection its timeouts; on failure the connection is closed and the
/// error returned (an accepted socket without timeouts could freeze the event loop for good).
///
/// # Safety
/// `client_fd` must be an open socket owned by the caller.
pub(crate) unsafe fn configure_accepted(client_fd: i32) -> Result<()> {
    if let Err(e) = set_io_timeouts(client_fd, ACCEPTED_IO_TIMEOUT_SECS) {
        libc::close(client_fd);
        return Err(Error::from_reason(format!(
            "setsockopt(SO_RCVTIMEO/SO_SNDTIMEO) on an accepted connection failed: {}",
            e
        )));
    }
    Ok(())
}

/// Give a freshly connected socket its timeouts (`timeout_secs`, else DEFAULT_IO_TIMEOUT_SECS);
/// on failure the socket is closed and the error returned.
///
/// # Safety
/// `fd` must be an open socket owned by the caller.
pub(crate) unsafe fn configure_connected(fd: i32, timeout_secs: Option<u32>) -> Result<()> {
    if let Err(e) = set_io_timeouts(fd, timeout_secs.unwrap_or(DEFAULT_IO_TIMEOUT_SECS)) {
        libc::close(fd);
        return Err(Error::from_reason(format!(
            "setsockopt(SO_RCVTIMEO/SO_SNDTIMEO) failed: {}",
            e
        )));
    }
    Ok(())
}

/// sockaddr_vm layout (from linux/vm_sockets.h)
#[repr(C)]
struct SockaddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

/// A vsock server that listens for incoming connections.
#[napi]
pub struct VsockListener {
    fd: AtomicI32,
}

#[napi]
impl VsockListener {
    /// Create a new VsockListener bound to CID_ANY on the given port.
    /// CID_ANY means the enclave accepts connections from any CID (typically the host).
    #[napi(factory)]
    pub fn bind(port: u32) -> Result<Self> {
        unsafe {
            let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(Error::from_reason(format!(
                    "socket(AF_VSOCK) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Allow address reuse
            let optval: i32 = 1;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as u32,
            );

            let addr = SockaddrVm {
                svm_family: AF_VSOCK as u16,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: VMADDR_CID_ANY,
                svm_zero: [0; 4],
            };

            let ret = libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as u32,
            );
            if ret < 0 {
                libc::close(fd);
                return Err(Error::from_reason(format!(
                    "bind(AF_VSOCK, port={}) failed: {}",
                    port,
                    std::io::Error::last_os_error()
                )));
            }

            let ret = libc::listen(fd, 128);
            if ret < 0 {
                libc::close(fd);
                return Err(Error::from_reason(format!(
                    "listen() failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            Ok(VsockListener { fd: AtomicI32::new(fd) })
        }
    }

    /// Accept a new connection. Blocks until a connection arrives.
    /// Returns a VsockStream for the accepted connection.
    #[napi]
    pub fn accept(&self) -> Result<VsockStream> {
        let fd = self.fd.load(Ordering::Acquire);
        if fd == CLOSED_FD {
            return Err(Error::from_reason("Listener already closed"));
        }
        unsafe {
            let mut addr: SockaddrVm = std::mem::zeroed();
            let mut addr_len = std::mem::size_of::<SockaddrVm>() as u32;

            let client_fd = libc::accept(
                fd,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            );
            if client_fd < 0 {
                return Err(Error::from_reason(format!(
                    "accept() failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            configure_accepted(client_fd)?;

            Ok(VsockStream {
                fd: AtomicI32::new(client_fd),
                peer_cid: addr.svm_cid,
                peer_port: addr.svm_port,
            })
        }
    }

    /// Accept a new connection asynchronously.
    /// Runs libc::accept on the libuv thread pool so the Node.js event loop
    /// stays free for concurrent handler I/O.
    #[napi(ts_return_type = "Promise<VsockStream>")]
    pub fn accept_async(&self) -> AsyncTask<AcceptTask> {
        AsyncTask::new(AcceptTask {
            fd: self.fd.load(Ordering::Acquire),
        })
    }

    /// Close the listener. Safe to call multiple times.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let fd = self.fd.swap(CLOSED_FD, Ordering::AcqRel);
        if fd != CLOSED_FD {
            unsafe { libc::close(fd); }
        }
        Ok(())
    }
}

pub struct AcceptTask {
    fd: i32,
}

impl Task for AcceptTask {
    type Output = (i32, u32, u32);
    type JsValue = VsockStream;

    fn compute(&mut self) -> Result<Self::Output> {
        if self.fd == CLOSED_FD {
            return Err(Error::from_reason("Listener already closed"));
        }
        unsafe {
            let mut addr: SockaddrVm = std::mem::zeroed();
            let mut addr_len = std::mem::size_of::<SockaddrVm>() as u32;

            let client_fd = libc::accept(
                self.fd,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut addr_len,
            );
            if client_fd < 0 {
                return Err(Error::from_reason(format!(
                    "accept() failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Timeouts on both directions, so libc::read / libc::write in readMessage / writeMessage
            // return EAGAIN instead of blocking forever when the peer connects and goes quiet or
            // stops reading. A stuck call freezes the Node.js event loop: withTimeout's setTimeout
            // cannot fire while it blocks.
            configure_accepted(client_fd)?;

            Ok((client_fd, addr.svm_cid, addr.svm_port))
        }
    }

    fn resolve(&mut self, _env: Env, (fd, cid, port): Self::Output) -> Result<Self::JsValue> {
        Ok(VsockStream {
            fd: AtomicI32::new(fd),
            peer_cid: cid,
            peer_port: port,
        })
    }
}

/// A connected vsock stream (either from accept() or connect()).
/// Supports binary read/write for use as a Node.js Duplex transport.
#[napi]
pub struct VsockStream {
    fd: AtomicI32,
    peer_cid: u32,
    peer_port: u32,
}

#[napi]
impl VsockStream {
    /// Connect to a vsock endpoint at the given CID and port.
    /// CID 3 = host (parent) from inside the enclave.
    /// Every read and write on the stream gives up after `timeout_secs` (default 30): without it a
    /// host proxy that accepts and goes silent would block libc::read on the event loop forever.
    #[napi(factory)]
    pub fn connect(cid: u32, port: u32, timeout_secs: Option<u32>) -> Result<Self> {
        unsafe {
            let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return Err(Error::from_reason(format!(
                    "socket(AF_VSOCK) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let addr = SockaddrVm {
                svm_family: AF_VSOCK as u16,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: cid,
                svm_zero: [0; 4],
            };

            let ret = libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as u32,
            );
            if ret < 0 {
                libc::close(fd);
                return Err(Error::from_reason(format!(
                    "connect(cid={}, port={}) failed: {}",
                    cid,
                    port,
                    std::io::Error::last_os_error()
                )));
            }
            configure_connected(fd, timeout_secs)?;

            Ok(VsockStream {
                fd: AtomicI32::new(fd),
                peer_cid: cid,
                peer_port: port,
            })
        }
    }

    /// Read up to `size` bytes from the stream.
    /// Returns a Buffer with the bytes read (may be fewer than `size`).
    /// Note: this is a blocking call (libc::read).
    #[napi]
    pub fn read(&self, size: u32) -> Result<Buffer> {
        let fd = self.fd.load(Ordering::Acquire);
        if fd == CLOSED_FD {
            return Ok(Buffer::from(Vec::<u8>::new()));
        }
        let mut buf = vec![0u8; size as usize];
        unsafe {
            let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            if n < 0 {
                return Err(Error::from_reason(format!(
                    "read() failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if n == 0 {
                return Ok(Buffer::from(Vec::<u8>::new()));
            }
            buf.truncate(n as usize);
            Ok(Buffer::from(buf))
        }
    }

    /// Write bytes to the stream. Returns number of bytes written.
    #[napi]
    pub fn write(&self, data: Buffer) -> Result<u32> {
        let fd = self.fd.load(Ordering::Acquire);
        if fd == CLOSED_FD {
            return Err(Error::from_reason("Stream already closed"));
        }
        unsafe {
            let n = libc::write(
                fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
            );
            if n < 0 {
                return Err(Error::from_reason(format!(
                    "write() failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(n as u32)
        }
    }

    /// Close the stream. Safe to call multiple times.
    #[napi]
    pub fn close(&self) -> Result<()> {
        let fd = self.fd.swap(CLOSED_FD, Ordering::AcqRel);
        if fd != CLOSED_FD {
            unsafe { libc::close(fd); }
        }
        Ok(())
    }

    /// Get the file descriptor (for polling or advanced use).
    #[napi(getter)]
    pub fn fd(&self) -> i32 {
        self.fd.load(Ordering::Acquire)
    }

    /// Get the peer CID.
    #[napi(getter)]
    pub fn peer_cid(&self) -> u32 {
        self.peer_cid
    }

    /// Get the peer port.
    #[napi(getter)]
    pub fn peer_port(&self) -> u32 {
        self.peer_port
    }
}

/// Connect to a vsock endpoint asynchronously with a kernel-level timeout.
/// Runs socket + connect on the libuv thread pool.
#[napi(ts_return_type = "Promise<VsockStream>")]
pub fn vsock_connect_async(cid: u32, port: u32, timeout_secs: Option<u32>) -> AsyncTask<ConnectTask> {
    AsyncTask::new(ConnectTask {
        cid,
        port,
        timeout_secs: timeout_secs.unwrap_or(5),
    })
}

pub struct ConnectTask {
    cid: u32,
    port: u32,
    timeout_secs: u32,
}

impl Task for ConnectTask {
    type Output = (i32, u32, u32);
    type JsValue = VsockStream;

    fn compute(&mut self) -> Result<Self::Output> {
        unsafe {
            // Non-blocking socket for connect-with-timeout via poll()
            let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
            if fd < 0 {
                return Err(Error::from_reason(format!(
                    "socket(AF_VSOCK) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let addr = SockaddrVm {
                svm_family: AF_VSOCK as u16,
                svm_reserved1: 0,
                svm_port: self.port,
                svm_cid: self.cid,
                svm_zero: [0; 4],
            };

            let ret = libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrVm>() as u32,
            );

            if ret < 0 {
                let err = *libc::__errno_location();
                if err != libc::EINPROGRESS {
                    libc::close(fd);
                    return Err(Error::from_reason(format!(
                        "connect(cid={}, port={}) failed: {}",
                        self.cid, self.port,
                        std::io::Error::from_raw_os_error(err)
                    )));
                }

                // Wait for connect to complete with poll(), retrying on EINTR
                let deadline = std::time::Instant::now()
                    + std::time::Duration::from_secs(self.timeout_secs as u64);
                loop {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    let remaining_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
                    if remaining_ms <= 0 {
                        libc::close(fd);
                        return Err(Error::from_reason(format!(
                            "connect(cid={}, port={}) timed out after {}s",
                            self.cid, self.port, self.timeout_secs
                        )));
                    }

                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    let poll_ret = libc::poll(&mut pfd, 1, remaining_ms);

                    if poll_ret < 0 {
                        let poll_err = *libc::__errno_location();
                        if poll_err == libc::EINTR {
                            continue;
                        }
                        libc::close(fd);
                        return Err(Error::from_reason(format!(
                            "poll() failed during connect(cid={}, port={}): {}",
                            self.cid, self.port,
                            std::io::Error::from_raw_os_error(poll_err)
                        )));
                    }
                    if poll_ret == 0 {
                        libc::close(fd);
                        return Err(Error::from_reason(format!(
                            "connect(cid={}, port={}) timed out after {}s",
                            self.cid, self.port, self.timeout_secs
                        )));
                    }
                    break;
                }

                // Check for connect error via SO_ERROR
                let mut so_err: i32 = 0;
                let mut len = std::mem::size_of::<i32>() as u32;
                let gs_ret = libc::getsockopt(
                    fd, libc::SOL_SOCKET, libc::SO_ERROR,
                    &mut so_err as *mut _ as *mut libc::c_void,
                    &mut len,
                );
                if gs_ret < 0 {
                    libc::close(fd);
                    return Err(Error::from_reason(format!(
                        "getsockopt(SO_ERROR) failed after connect(cid={}, port={}): {}",
                        self.cid, self.port,
                        std::io::Error::last_os_error()
                    )));
                }
                if so_err != 0 {
                    libc::close(fd);
                    return Err(Error::from_reason(format!(
                        "connect(cid={}, port={}) failed: {}",
                        self.cid, self.port,
                        std::io::Error::from_raw_os_error(so_err)
                    )));
                }
            }

            // Clear non-blocking flag for subsequent blocking read/write
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                libc::close(fd);
                return Err(Error::from_reason(format!(
                    "fcntl(F_GETFL) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let fl_ret = libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
            if fl_ret < 0 {
                libc::close(fd);
                return Err(Error::from_reason(format!(
                    "fcntl(F_SETFL) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            // Set I/O timeouts for subsequent read/write operations
            configure_connected(fd, Some(self.timeout_secs))?;

            Ok((fd, self.cid, self.port))
        }
    }

    fn resolve(&mut self, _env: Env, (fd, cid, port): Self::Output) -> Result<Self::JsValue> {
        Ok(VsockStream {
            fd: AtomicI32::new(fd),
            peer_cid: cid,
            peer_port: port,
        })
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        let fd = self.fd.swap(CLOSED_FD, Ordering::AcqRel);
        if fd != CLOSED_FD {
            unsafe { libc::close(fd); }
        }
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        let fd = self.fd.swap(CLOSED_FD, Ordering::AcqRel);
        if fd != CLOSED_FD {
            unsafe { libc::close(fd); }
        }
    }
}

// =============================================================================
// Tests — run via `cargo test` (inside Docker build or CI)
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Struct layout: SockaddrVm must match the Linux kernel's sockaddr_vm
    // -------------------------------------------------------------------------

    #[test]
    fn sockaddr_vm_size_matches_kernel() {
        // Linux sockaddr_vm is 16 bytes on all architectures:
        //   svm_family(2) + svm_reserved1(2) + svm_port(4) + svm_cid(4) + svm_zero(4) = 16
        assert_eq!(std::mem::size_of::<SockaddrVm>(), 16);
    }

    #[test]
    fn sockaddr_vm_alignment_is_natural() {
        assert_eq!(std::mem::align_of::<SockaddrVm>(), 4);
    }

    #[test]
    fn sockaddr_vm_field_offsets() {
        let addr = SockaddrVm {
            svm_family: 0,
            svm_reserved1: 0,
            svm_port: 0,
            svm_cid: 0,
            svm_zero: [0; 4],
        };
        let base = &addr as *const _ as usize;
        assert_eq!(&addr.svm_family as *const _ as usize - base, 0);
        assert_eq!(&addr.svm_reserved1 as *const _ as usize - base, 2);
        assert_eq!(&addr.svm_port as *const _ as usize - base, 4);
        assert_eq!(&addr.svm_cid as *const _ as usize - base, 8);
        assert_eq!(&addr.svm_zero as *const _ as usize - base, 12);
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    #[test]
    fn af_vsock_matches_linux_constant() {
        assert_eq!(AF_VSOCK, 40);
    }

    #[test]
    fn vmaddr_cid_any_matches_linux_constant() {
        assert_eq!(VMADDR_CID_ANY, 0xFFFFFFFF);
    }

    #[test]
    fn closed_fd_is_negative() {
        assert_eq!(CLOSED_FD, -1);
    }

    // -------------------------------------------------------------------------
    // ConnectTask: non-blocking connect + poll pattern
    // -------------------------------------------------------------------------

    #[test]
    fn connect_task_stores_params() {
        let task = ConnectTask { cid: 16, port: 5000, timeout_secs: 5 };
        assert_eq!(task.cid, 16);
        assert_eq!(task.port, 5000);
        assert_eq!(task.timeout_secs, 5);
    }

    #[test]
    #[ignore] // Requires vhost_vsock kernel module (available in Nitro Enclaves, not CI)
    fn connect_task_to_invalid_cid_fails() {
        let mut task = ConnectTask { cid: 0, port: 5000, timeout_secs: 1 };
        let result = task.compute();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().reason;
        assert!(err_msg.contains("cid=0"), "error should mention cid: {}", err_msg);
        assert!(err_msg.contains("port=5000"), "error should mention port: {}", err_msg);
    }

    #[test]
    #[ignore] // Requires vhost_vsock kernel module (available in Nitro Enclaves, not CI)
    fn connect_task_timeout_on_unreachable_cid() {
        let mut task = ConnectTask { cid: 99, port: 5000, timeout_secs: 1 };
        let start = std::time::Instant::now();
        let result = task.compute();
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(elapsed.as_secs() <= 3, "took too long: {:?}", elapsed);
    }

    // -------------------------------------------------------------------------
    // AcceptTask
    // -------------------------------------------------------------------------

    #[test]
    fn accept_task_with_closed_fd_fails() {
        let mut task = AcceptTask { fd: CLOSED_FD };
        let result = task.compute();
        assert!(result.is_err());
        assert!(result.unwrap_err().reason.contains("closed"));
    }

    #[test]
    fn accept_task_with_invalid_fd_fails() {
        // fd 999999 is almost certainly not a valid listener
        let mut task = AcceptTask { fd: 999999 };
        let result = task.compute();
        assert!(result.is_err());
        assert!(result.unwrap_err().reason.contains("accept()"));
    }

    // -------------------------------------------------------------------------
    // Non-blocking connect + poll pattern (using TCP as proxy for AF_VSOCK)
    // Validates the poll-based timeout works correctly with any socket type.
    // -------------------------------------------------------------------------

    #[test]
    fn nonblocking_connect_poll_timeout_with_tcp() {
        // Use a TCP socket to an unroutable address to test the poll timeout pattern.
        // 192.0.2.1 is TEST-NET-1 (RFC 5737), should be unreachable.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
            assert!(fd >= 0, "socket() failed");

            let addr = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 9999u16.to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from_be_bytes([192, 0, 2, 1]).to_be() },
                sin_zero: [0; 8],
            };

            let ret = libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            );

            if ret < 0 {
                let err = *libc::__errno_location();
                assert_eq!(err, libc::EINPROGRESS, "expected EINPROGRESS, got {}", err);

                let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                let start = std::time::Instant::now();
                let poll_ret = libc::poll(&mut pfd, 1, 500); // 500ms timeout
                let elapsed = start.elapsed();

                // poll should timeout (return 0) or connect-fail (return 1 with SO_ERROR)
                assert!(poll_ret >= 0, "poll() failed");
                if poll_ret == 0 {
                    // Timeout path — verify it respected the 500ms
                    assert!(elapsed.as_millis() >= 400, "poll returned too early: {:?}", elapsed);
                    assert!(elapsed.as_millis() <= 1500, "poll took too long: {:?}", elapsed);
                }
            }

            libc::close(fd);
        }
    }

    // -------------------------------------------------------------------------
    // I/O timeouts (socketpair stands in for AF_VSOCK: SO_RCVTIMEO/SO_SNDTIMEO behave the same)
    // -------------------------------------------------------------------------

    fn socketpair() -> (i32, i32) {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair() failed: {}", std::io::Error::last_os_error());
        (fds[0], fds[1])
    }

    fn timeout_secs_of(fd: i32, opt: i32) -> libc::time_t {
        let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
        let mut len = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, opt, &mut tv as *mut _ as *mut libc::c_void, &mut len)
        };
        assert_eq!(ret, 0, "getsockopt() failed: {}", std::io::Error::last_os_error());
        tv.tv_sec
    }

    #[test]
    fn set_io_timeouts_sets_rcv_and_snd() {
        let (a, b) = socketpair();
        unsafe { set_io_timeouts(a, 3) }.expect("set_io_timeouts");
        assert_eq!(timeout_secs_of(a, libc::SO_RCVTIMEO), 3);
        assert_eq!(timeout_secs_of(a, libc::SO_SNDTIMEO), 3);
        unsafe { libc::close(a); libc::close(b); }
    }

    #[test]
    fn set_io_timeouts_never_sets_zero_which_means_forever() {
        let (a, b) = socketpair();
        unsafe { set_io_timeouts(a, 0) }.expect("set_io_timeouts");
        assert_eq!(timeout_secs_of(a, libc::SO_RCVTIMEO), 1);
        assert_eq!(timeout_secs_of(a, libc::SO_SNDTIMEO), 1);
        unsafe { libc::close(a); libc::close(b); }
    }

    #[test]
    fn read_on_idle_socket_returns_within_timeout() {
        let (a, b) = socketpair();
        unsafe { set_io_timeouts(a, 1) }.expect("set_io_timeouts");
        let mut buf = [0u8; 16];
        let start = std::time::Instant::now();
        let n = unsafe { libc::read(a, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        let err = std::io::Error::last_os_error();
        let elapsed = start.elapsed();
        assert_eq!(n, -1, "an idle read must fail, not return data");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock, "expected EAGAIN, got {}", err);
        assert!(elapsed.as_millis() >= 900, "returned too early: {:?}", elapsed);
        assert!(elapsed.as_millis() < 2500, "took too long: {:?}", elapsed);
        unsafe { libc::close(a); libc::close(b); }
    }

    #[test]
    fn configure_connected_defaults_to_30_seconds() {
        let (a, b) = socketpair();
        unsafe { configure_connected(a, None) }.expect("configure_connected");
        assert_eq!(timeout_secs_of(a, libc::SO_RCVTIMEO), DEFAULT_IO_TIMEOUT_SECS as libc::time_t);
        assert_eq!(timeout_secs_of(a, libc::SO_SNDTIMEO), DEFAULT_IO_TIMEOUT_SECS as libc::time_t);
        assert_eq!(DEFAULT_IO_TIMEOUT_SECS, 30);
        unsafe { libc::close(a); libc::close(b); }
    }

    #[test]
    fn configure_connected_uses_the_callers_timeout() {
        let (a, b) = socketpair();
        unsafe { configure_connected(a, Some(7)) }.expect("configure_connected");
        assert_eq!(timeout_secs_of(a, libc::SO_RCVTIMEO), 7);
        assert_eq!(timeout_secs_of(a, libc::SO_SNDTIMEO), 7);
        unsafe { libc::close(a); libc::close(b); }
    }

    #[test]
    fn configure_accepted_sets_both_directions() {
        let (a, b) = socketpair();
        unsafe { configure_accepted(a) }.expect("configure_accepted");
        assert_eq!(timeout_secs_of(a, libc::SO_RCVTIMEO), ACCEPTED_IO_TIMEOUT_SECS as libc::time_t);
        assert_eq!(timeout_secs_of(a, libc::SO_SNDTIMEO), ACCEPTED_IO_TIMEOUT_SECS as libc::time_t);
        assert_eq!(ACCEPTED_IO_TIMEOUT_SECS, 10);
        unsafe { libc::close(a); libc::close(b); }
    }

    /// The pipe whose write end is `w` still has a reader: once every read end is closed, a write fails with EPIPE (the
    /// test harness ignores SIGPIPE, as every Rust program does). A check on the read end's fd NUMBER failed in CI: a
    /// test on another thread opened a file that took the freed number.
    fn has_reader(w: i32) -> bool {
        let n = unsafe { libc::write(w, b"x".as_ptr() as *const libc::c_void, 1) };
        if n == 1 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::EPIPE), "write to the pipe: {}", err);
        false
    }

    fn pipe() -> (i32, i32) {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe() failed: {}", std::io::Error::last_os_error());
        (fds[0], fds[1])
    }

    #[test]
    fn configure_accepted_closes_the_fd_when_it_cannot_set_timeouts() {
        // A pipe is not a socket: setsockopt fails (ENOTSOCK), the error names the cause, the fd is closed.
        let (r, w) = pipe();
        let result = unsafe { configure_accepted(r) };
        assert!(result.is_err());
        assert!(result.unwrap_err().reason.contains("accepted connection"));
        assert!(!has_reader(w), "the fd must be closed");
        unsafe { libc::close(w); }
    }

    #[test]
    fn configure_connected_closes_the_fd_when_it_cannot_set_timeouts() {
        let (r, w) = pipe();
        let result = unsafe { configure_connected(r, Some(5)) };
        assert!(result.is_err());
        assert!(!has_reader(w), "the fd must be closed");
        unsafe { libc::close(w); }
    }

    // -------------------------------------------------------------------------
    // Send/Sync: tasks must be Send for napi-rs thread pool
    // -------------------------------------------------------------------------

    fn assert_send<T: Send>() {}

    #[test]
    fn accept_task_is_send() {
        assert_send::<AcceptTask>();
    }

    #[test]
    fn connect_task_is_send() {
        assert_send::<ConnectTask>();
    }
}
