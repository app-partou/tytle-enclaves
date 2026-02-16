use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::sync::atomic::{AtomicI32, Ordering};

/// AF_VSOCK constants — not in libc crate, defined by Linux kernel
const AF_VSOCK: i32 = 40;
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

/// Sentinel value indicating the fd has been closed.
const CLOSED_FD: i32 = -1;

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
        let fd = self.fd.load(Ordering::Relaxed);
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

            Ok(VsockStream {
                fd: AtomicI32::new(client_fd),
                peer_cid: addr.svm_cid,
                peer_port: addr.svm_port,
            })
        }
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
    #[napi(factory)]
    pub fn connect(cid: u32, port: u32) -> Result<Self> {
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
        let fd = self.fd.load(Ordering::Relaxed);
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
        let fd = self.fd.load(Ordering::Relaxed);
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
        self.fd.load(Ordering::Relaxed)
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
