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

/// Read/write timeout of an accepted connection. A backstop only: `read_within` and `write_within` wait in
/// poll(2) for at most the time their caller gives, and their recv/send never block (MSG_DONTWAIT), so these
/// socket timeouts no longer bound anything they do.
const ACCEPTED_IO_TIMEOUT_SECS: u32 = 10;

/// The wall clock in milliseconds since the epoch: what JavaScript's `Date.now()` reads (both read CLOCK_REALTIME).
fn now_epoch_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as f64)
        .unwrap_or(0.0)
}

/// An I/O error as the JS side sees it: "<what> failed: <the OS's reason>".
fn io_error(what: &str, e: std::io::Error) -> Error {
    Error::from_reason(format!("{} failed: {}", what, e))
}

/// Wait until `fd` is ready for `events` (POLLIN or POLLOUT), for at most `timeout_ms`. A signal does not end the
/// wait early: poll is asked again for the time left (enclave review 2026-10-09, E1 F-11: with a socket timeout set,
/// the kernel answers EINTR instead of restarting the call). `Ok(true)`: ready, or an error or hang-up that the next
/// call reports; `Ok(false)`: the time ran out.
fn wait_ready(fd: i32, events: i16, timeout_ms: u32) -> std::io::Result<bool> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
    loop {
        let left_ms = deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd { fd, events, revents: 0 };
        let ret = unsafe { libc::poll(&mut pfd, 1, left_ms) };
        if ret > 0 {
            return Ok(true);
        }
        if ret == 0 {
            return Ok(false);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

/// Read up to `size` bytes from `fd`, waiting at most `timeout_ms` for the peer: the bytes (empty at the end of the
/// stream), or None when nothing came in time. The read itself never blocks (MSG_DONTWAIT); a signal does not end it.
/// Plain Rust, no Node values: its tests run without Node.
fn recv_within(fd: i32, size: usize, timeout_ms: u32) -> Result<Option<Vec<u8>>> {
    if !wait_ready(fd, libc::POLLIN, timeout_ms).map_err(|e| io_error("poll() before a read", e))? {
        return Ok(None);
    }
    let mut buf = vec![0u8; size];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT) };
        if n >= 0 {
            buf.truncate(n as usize);
            return Ok(Some(buf));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(None),
            _ => return Err(io_error("read()", err)),
        }
    }
}

/// Write as much of `data` to `fd` as the peer takes, waiting at most `timeout_ms` for room: the number of bytes
/// written, 0 when the peer took nothing in time. The write itself never blocks (MSG_DONTWAIT) and never raises
/// SIGPIPE (MSG_NOSIGNAL); a signal does not end it. Plain Rust, no Node values: its tests run without Node.
fn send_within(fd: i32, data: &[u8], timeout_ms: u32) -> Result<u32> {
    if !wait_ready(fd, libc::POLLOUT, timeout_ms).map_err(|e| io_error("poll() before a write", e))? {
        return Ok(0);
    }
    loop {
        let n = unsafe {
            libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
        };
        if n >= 0 {
            return Ok(n as u32);
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => return Ok(0),
            _ => return Err(io_error("write()", err)),
        }
    }
}

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
                opened_at_ms: now_epoch_ms(),
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
    type Output = (i32, u32, u32, f64);
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

            // The time the connection arrived, taken here, on the thread pool: the request's budget starts now, not
            // when the event loop gets to it (enclave review 2026-10-09, E-1).
            let accepted_at_ms = now_epoch_ms();

            // Socket timeouts on both directions, a backstop (ACCEPTED_IO_TIMEOUT_SECS).
            configure_accepted(client_fd)?;

            Ok((client_fd, addr.svm_cid, addr.svm_port, accepted_at_ms))
        }
    }

    fn resolve(&mut self, _env: Env, (fd, cid, port, opened_at_ms): Self::Output) -> Result<Self::JsValue> {
        Ok(VsockStream {
            fd: AtomicI32::new(fd),
            peer_cid: cid,
            peer_port: port,
            opened_at_ms,
        })
    }
}

/// A connected vsock stream (either from accept() or connect()).
/// Supports binary reads and writes, each waiting at most the time its caller gives, for use as a Node.js Duplex
/// transport and by the message framing (shared/src/vsockWait.ts).
#[napi]
pub struct VsockStream {
    fd: AtomicI32,
    peer_cid: u32,
    peer_port: u32,
    /// Epoch ms when the call that opened the stream returned (accept or connect)
    opened_at_ms: f64,
}

#[napi]
impl VsockStream {
    /// Connect to a vsock endpoint at the given CID and port.
    /// CID 3 = host (parent) from inside the enclave.
    /// `timeout_secs` (default 30) sets the socket's read and write timeouts, a backstop: `read_within` and
    /// `write_within` wait only the time their caller gives.
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
                opened_at_ms: now_epoch_ms(),
            })
        }
    }

    /// Read up to `size` bytes (at least 1), waiting at most `timeout_ms` for the peer.
    /// Returns the bytes read (maybe fewer than `size`), an empty Buffer at the end of the stream (or once the
    /// stream is closed), or null when nothing came in time.
    /// The wait is a poll(2) of at most `timeout_ms`, and the read itself never blocks (MSG_DONTWAIT). The event
    /// loop runs while a caller waits between calls: a read used to block it until the peer answered or the
    /// socket's timeout ran out, and no timer could stop it (enclave review 2026-10-09, E-1).
    #[napi]
    pub fn read_within(&self, size: u32, timeout_ms: u32) -> Result<Option<Buffer>> {
        Ok(self.read_bytes_within(size, timeout_ms)?.map(Buffer::from))
    }

    /// Write as much of `data` as the peer takes, waiting at most `timeout_ms` for room.
    /// Returns the number of bytes written: 0 when the peer took nothing in time.
    /// The wait is a poll(2) of at most `timeout_ms`; the write itself never blocks (MSG_DONTWAIT) and never raises
    /// SIGPIPE (MSG_NOSIGNAL): a peer that has gone is an error. A write used to block until the peer made room or
    /// the socket's timeout ran out, again and again for a peer that drains slowly (enclave review 2026-10-09,
    /// E1 F-10).
    #[napi]
    pub fn write_within(&self, data: Buffer, timeout_ms: u32) -> Result<u32> {
        self.write_bytes_within(&data, timeout_ms)
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

    /// Epoch ms when the call that opened the stream returned: for an accepted connection, the moment it arrived
    /// (taken on the thread pool, before the event loop gets to it).
    #[napi(getter)]
    pub fn opened_at_ms(&self) -> f64 {
        self.opened_at_ms
    }
}

/// The plain-Rust cores of `read_within` and `write_within` (no Node values, so their tests run without Node).
impl VsockStream {
    fn read_bytes_within(&self, size: u32, timeout_ms: u32) -> Result<Option<Vec<u8>>> {
        if size == 0 {
            return Err(Error::from_reason("read_within needs a size of at least 1 byte"));
        }
        let fd = self.fd.load(Ordering::Acquire);
        if fd == CLOSED_FD {
            return Ok(Some(Vec::new()));
        }
        recv_within(fd, size as usize, timeout_ms)
    }

    fn write_bytes_within(&self, data: &[u8], timeout_ms: u32) -> Result<u32> {
        let fd = self.fd.load(Ordering::Acquire);
        if fd == CLOSED_FD {
            return Err(Error::from_reason("Stream already closed"));
        }
        if data.is_empty() {
            return Ok(0);
        }
        send_within(fd, data, timeout_ms)
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
    type Output = (i32, u32, u32, f64);
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

            // Socket timeouts for reads and writes, a backstop (read_within / write_within wait as asked)
            configure_connected(fd, Some(self.timeout_secs))?;

            Ok((fd, self.cid, self.port, now_epoch_ms()))
        }
    }

    fn resolve(&mut self, _env: Env, (fd, cid, port, opened_at_ms): Self::Output) -> Result<Self::JsValue> {
        Ok(VsockStream {
            fd: AtomicI32::new(fd),
            peer_cid: cid,
            peer_port: port,
            opened_at_ms,
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
    // read_within / write_within: every wait is the caller's (enclave review 2026-10-09, E-1, E1 F-10, F-11)
    // -------------------------------------------------------------------------

    fn stream_on(fd: i32) -> VsockStream {
        VsockStream { fd: AtomicI32::new(fd), peer_cid: 0, peer_port: 0, opened_at_ms: 0.0 }
    }

    fn bytes_of(read: Result<Option<Vec<u8>>>) -> Option<Vec<u8>> {
        read.expect("read_within")
    }

    /// Fill `fd`'s send buffer until the peer takes no more; returns how many bytes went in.
    fn fill(fd: i32) -> usize {
        let chunk = [0u8; 65536];
        let mut total = 0;
        loop {
            let n = unsafe { libc::send(fd, chunk.as_ptr() as *const libc::c_void, chunk.len(), libc::MSG_DONTWAIT) };
            if n <= 0 {
                return total;
            }
            total += n as usize;
        }
    }

    extern "C" fn ignore_signal(_: i32) {}

    /// SIGUSR1 handled with SA_RESTART, as Node's handlers are: a call with a socket timeout set still ends with EINTR.
    fn handle_sigusr1() {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = ignore_signal as usize;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()), 0);
        }
    }

    /// Send SIGUSR1 to the calling thread after `after_ms`.
    fn signal_me_after(after_ms: u64) -> std::thread::JoinHandle<()> {
        let me = unsafe { libc::pthread_self() } as usize;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(after_ms));
            unsafe { libc::pthread_kill(me as libc::pthread_t, libc::SIGUSR1) };
        })
    }

    #[test]
    fn read_within_returns_what_is_there_at_once() {
        let (a, b) = socketpair();
        let s = stream_on(a);
        assert_eq!(unsafe { libc::write(b, b"hello".as_ptr() as *const libc::c_void, 5) }, 5);
        let start = std::time::Instant::now();
        assert_eq!(bytes_of(s.read_bytes_within(64, 5_000)), Some(b"hello".to_vec()));
        assert!(start.elapsed().as_millis() < 500, "waited although the bytes were there: {:?}", start.elapsed());
        unsafe { libc::close(b); }
    }

    #[test]
    fn read_within_gives_null_once_its_time_is_up_and_never_waits_for_the_socket_timeout() {
        // The socket's own timeout is 10 s (a backstop); the caller gives 300 ms, and 300 ms is what it waits.
        let (a, b) = socketpair();
        unsafe { set_io_timeouts(a, 10) }.expect("set_io_timeouts");
        let s = stream_on(a);
        let start = std::time::Instant::now();
        assert_eq!(bytes_of(s.read_bytes_within(64, 300)), None);
        let waited = start.elapsed().as_millis();
        assert!((250..2_000).contains(&waited), "waited {} ms for a 300 ms read", waited);
        unsafe { libc::close(b); }
    }

    #[test]
    fn read_within_gives_an_empty_buffer_at_the_end_of_the_stream() {
        let (a, b) = socketpair();
        let s = stream_on(a);
        unsafe { libc::close(b); }
        assert_eq!(bytes_of(s.read_bytes_within(64, 1_000)), Some(Vec::new()));
    }

    #[test]
    fn read_within_on_a_closed_stream_is_the_end_of_the_stream_and_touches_no_fd() {
        let (a, b) = socketpair();
        let s = stream_on(a);
        s.close().expect("close");
        assert_eq!(bytes_of(s.read_bytes_within(64, 1_000)), Some(Vec::new()));
        unsafe { libc::close(b); }
    }

    #[test]
    fn read_within_refuses_a_size_of_zero() {
        let (a, b) = socketpair();
        let s = stream_on(a);
        assert!(s.read_bytes_within(0, 100).is_err());
        unsafe { libc::close(b); }
    }

    #[test]
    fn read_within_is_not_ended_by_a_signal() {
        // E1 F-11: with a socket timeout set, a blocking read ended with EINTR at the signal (a failed request).
        handle_sigusr1();
        let (a, b) = socketpair();
        unsafe { set_io_timeouts(a, 10) }.expect("set_io_timeouts");
        let s = stream_on(a);
        let signaller = signal_me_after(100);
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            unsafe { libc::write(b, b"late".as_ptr() as *const libc::c_void, 4) };
            b
        });
        let start = std::time::Instant::now();
        assert_eq!(bytes_of(s.read_bytes_within(64, 3_000)), Some(b"late".to_vec()));
        assert!(start.elapsed().as_millis() >= 250, "returned before the bytes came: {:?}", start.elapsed());
        signaller.join().unwrap();
        let b = writer.join().unwrap();
        unsafe { libc::close(b); }
    }

    #[test]
    fn read_within_still_ends_on_time_when_a_signal_comes_while_it_waits() {
        handle_sigusr1();
        let (a, b) = socketpair();
        let s = stream_on(a);
        let signaller = signal_me_after(100);
        let start = std::time::Instant::now();
        assert_eq!(bytes_of(s.read_bytes_within(64, 400)), None);
        let waited = start.elapsed().as_millis();
        assert!((350..2_000).contains(&waited), "waited {} ms for a 400 ms read with a signal at 100 ms", waited);
        signaller.join().unwrap();
        unsafe { libc::close(b); }
    }

    #[test]
    fn write_within_writes_what_the_peer_takes() {
        let (a, b) = socketpair();
        let s = stream_on(a);
        assert_eq!(s.write_bytes_within(b"ping", 1_000).expect("write_within"), 4);
        let mut buf = [0u8; 8];
        assert_eq!(unsafe { libc::read(b, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }, 4);
        assert_eq!(&buf[..4], b"ping");
        unsafe { libc::close(b); }
    }

    #[test]
    fn write_within_gives_zero_once_its_time_is_up_for_a_peer_that_does_not_read() {
        let (a, b) = socketpair();
        unsafe { set_io_timeouts(a, 10) }.expect("set_io_timeouts");
        let s = stream_on(a);
        assert!(fill(a) > 0);
        let start = std::time::Instant::now();
        assert_eq!(s.write_bytes_within(&[1u8; 1024], 300).expect("write_within"), 0);
        let waited = start.elapsed().as_millis();
        assert!((250..2_000).contains(&waited), "waited {} ms for a 300 ms write", waited);
        unsafe { libc::close(b); }
    }

    #[test]
    fn write_within_to_a_peer_that_has_gone_is_an_error_not_a_signal() {
        let (a, b) = socketpair();
        let s = stream_on(a);
        unsafe { libc::close(b); }
        let result = s.write_bytes_within(b"x", 1_000);
        assert!(result.is_err(), "a write to a closed peer must fail");
        assert!(result.unwrap_err().reason.contains("write() failed"));
    }

    #[test]
    fn write_within_on_a_closed_stream_is_an_error() {
        let (a, b) = socketpair();
        let s = stream_on(a);
        s.close().expect("close");
        assert!(s.write_bytes_within(b"x", 100).is_err());
        unsafe { libc::close(b); }
    }

    // -------------------------------------------------------------------------
    // The time a connection arrived (enclave review 2026-10-09, E-1: the budget starts at the native accept)
    // -------------------------------------------------------------------------

    #[test]
    fn accept_task_takes_the_time_the_connection_arrived() {
        // An AF_UNIX listener stands in for AF_VSOCK: accept(2) and the timeouts behave the same.
        unsafe {
            let listener = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            assert!(listener >= 0);
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path = format!("/tmp/vsock-test-{}-{}.sock", std::process::id(), listener);
            for (i, byte) in path.as_bytes().iter().enumerate() {
                addr.sun_path[i] = *byte as libc::c_char;
            }
            let len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            assert_eq!(libc::bind(listener, &addr as *const _ as *const libc::sockaddr, len), 0);
            assert_eq!(libc::listen(listener, 1), 0);
            let client = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            assert_eq!(libc::connect(client, &addr as *const _ as *const libc::sockaddr, len), 0);

            let before = now_epoch_ms();
            let (fd, _, _, accepted_at_ms) = AcceptTask { fd: listener }.compute().expect("accept");
            let after = now_epoch_ms();
            assert!(accepted_at_ms >= before && accepted_at_ms <= after, "{} not in [{}, {}]", accepted_at_ms, before, after);

            libc::close(fd);
            libc::close(client);
            libc::close(listener);
            let c_path = std::ffi::CString::new(path).unwrap();
            libc::unlink(c_path.as_ptr());
        }
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
