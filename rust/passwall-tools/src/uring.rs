//! One-shot socket I/O on io_uring.
//!
//! The ring is single-issuer, with cooperative and deferred task work, so the
//! kernel does not interrupt the probe thread for each completion. The socket
//! is a registered file and the transfer buffer is a registered buffer, which
//! skips the per-operation fd table and page-pin lookups.
//!
//! SQPOLL is left off. A probe spends almost all of its time waiting on the
//! network, and a kernel polling thread would sit on a router core between
//! those round trips.

use std::io::{self, ErrorKind, Read, Write};
use std::mem;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;
use std::time::{Duration, Instant};

use io_uring::opcode::{Connect, LinkTimeout, Recv, Send};
use io_uring::squeue::{Entry, Flags};
use io_uring::types::{self, Timespec};
use io_uring::{IoUring, Probe};

const BUF_LEN: usize = 16 * 1024;

pub struct UringSock {
    ring: IoUring,
    fd: OwnedFd,
    buf: Box<[u8]>,
    deadline: Instant,
    ts: Timespec,
    fixed: bool,
}

impl UringSock {
    pub fn connect(addr: SocketAddr, timeout: Duration, deadline: Instant) -> io::Result<Self> {
        let fd = open_socket(addr)?;
        let ring = open_ring()?;
        if !opcodes_ready(&ring) {
            return Err(unsupported());
        }
        let buf = vec![0u8; BUF_LEN].into_boxed_slice();
        let fixed = register(&ring, fd.as_raw_fd(), &buf).is_ok();
        let connect_deadline =
            Instant::now() + timeout.min(deadline.saturating_duration_since(Instant::now()));
        if connect_deadline <= Instant::now() {
            return Err(timed_out());
        }
        let mut sock = UringSock {
            ring,
            fd,
            buf,
            deadline: connect_deadline,
            ts: Timespec::new(),
            fixed,
        };
        sock.connect_addr(addr)?;
        sock.deadline = deadline;
        sock.quickack();
        Ok(sock)
    }

    pub fn set_deadline(&mut self, start: Instant, budget: Duration) -> io::Result<()> {
        self.deadline = start + budget;
        if Instant::now() >= self.deadline {
            Err(timed_out())
        } else {
            Ok(())
        }
    }

    fn connect_addr(&mut self, addr: SocketAddr) -> io::Result<()> {
        let (storage, len) = store_addr(addr);
        let ptr = &storage as *const libc::sockaddr_storage as *const libc::sockaddr;
        let op = if self.fixed {
            Connect::new(types::Fixed(0), ptr, len).build()
        } else {
            Connect::new(types::Fd(self.fd.as_raw_fd()), ptr, len).build()
        };
        self.submit(op)?;
        Ok(())
    }

    fn submit(&mut self, op: Entry) -> io::Result<i32> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(timed_out());
        }
        self.ts = Timespec::from(left);
        let ts = &self.ts as *const Timespec;
        let op = op.flags(Flags::IO_LINK).user_data(1);
        let timeout = LinkTimeout::new(ts).build().user_data(2);
        unsafe {
            let mut sq = self.ring.submission();
            sq.push_multiple(&[op, timeout])
                .map_err(|_| io::Error::from_raw_os_error(libc::EAGAIN))?;
        }
        let mut expired = false;
        let mut op_res = None;
        let mut got = 0;
        while got < 2 {
            loop {
                match self.ring.submit_and_wait(1) {
                    Ok(_) => break,
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(err) => return Err(err),
                }
            }
            let mut cq = self.ring.completion();
            while let Some(cqe) = cq.next() {
                got += 1;
                if cqe.user_data() == 2 {
                    if cqe.result() == -libc::ETIME {
                        expired = true;
                    }
                } else {
                    op_res = Some(cqe.result());
                }
            }
        }
        let res = op_res.ok_or_else(unsupported)?;
        if res < 0 {
            let err = -res;
            if expired && matches!(err, libc::ECANCELED | libc::ETIME | libc::EINTR) {
                return Err(timed_out());
            }
            return Err(io::Error::from_raw_os_error(err));
        }
        Ok(res)
    }

    fn quickack(&self) {
        let one: i32 = 1;
        unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_QUICKACK,
                &one as *const i32 as *const libc::c_void,
                mem::size_of_val(&one) as libc::socklen_t,
            );
        }
    }

    fn send_entry(&self, ptr: *const u8, len: u32) -> Entry {
        // MSG_NOSIGNAL: a reset peer must not deliver SIGPIPE to the probe.
        let flags = libc::MSG_NOSIGNAL;
        if self.fixed {
            Send::new(types::Fixed(0), ptr, len).flags(flags).build()
        } else {
            Send::new(types::Fd(self.fd.as_raw_fd()), ptr, len)
                .flags(flags)
                .build()
        }
    }

    fn recv_entry(&self, ptr: *mut u8, len: u32) -> Entry {
        if self.fixed {
            Recv::new(types::Fixed(0), ptr, len).build()
        } else {
            Recv::new(types::Fd(self.fd.as_raw_fd()), ptr, len).build()
        }
    }
}

impl Read for UringSock {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        self.quickack();
        let n = out.len().min(self.buf.len());
        let ptr = self.buf.as_mut_ptr();
        let entry = self.recv_entry(ptr, n as u32);
        let got = self.submit(entry)? as usize;
        out[..got].copy_from_slice(&self.buf[..got]);
        Ok(got)
    }
}

impl Write for UringSock {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let n = data.len().min(self.buf.len());
        self.buf[..n].copy_from_slice(&data[..n]);
        let ptr = self.buf.as_ptr();
        let entry = self.send_entry(ptr, n as u32);
        Ok(self.submit(entry)? as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn open_ring() -> io::Result<IoUring> {
    let mut builder = IoUring::builder();
    builder
        .setup_single_issuer()
        .setup_coop_taskrun()
        .setup_defer_taskrun()
        .setup_submit_all()
        .setup_no_sqarray();
    builder.build(16).or_else(|_| IoUring::new(16))
}

fn opcodes_ready(ring: &IoUring) -> bool {
    let mut probe = Probe::new();
    if ring.submitter().register_probe(&mut probe).is_err() {
        return true;
    }
    probe.is_supported(Connect::CODE)
        && probe.is_supported(Send::CODE)
        && probe.is_supported(Recv::CODE)
        && probe.is_supported(LinkTimeout::CODE)
}

fn register(ring: &IoUring, fd: i32, buf: &[u8]) -> io::Result<()> {
    ring.submitter().register_files(&[fd])?;
    let iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    unsafe { ring.submitter().register_buffers(&[iov]) }
}

fn open_socket(addr: SocketAddr) -> io::Result<OwnedFd> {
    let domain = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let raw = unsafe { libc::socket(domain, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_int(fd.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_NODELAY, 1)?;
    set_int(fd.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_QUICKACK, 1)?;
    Ok(fd)
}

fn set_int(fd: i32, level: i32, name: i32, value: i32) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const i32 as *const libc::c_void,
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn store_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                ptr::copy_nonoverlapping(&sin, &mut storage as *mut _ as *mut libc::sockaddr_in, 1);
            }
            (
                storage,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(v6) => {
            let sin = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                ptr::copy_nonoverlapping(
                    &sin,
                    &mut storage as *mut _ as *mut libc::sockaddr_in6,
                    1,
                );
            }
            (
                storage,
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn unsupported() -> io::Error {
    io::Error::new(ErrorKind::Unsupported, "io_uring")
}

fn timed_out() -> io::Error {
    io::Error::new(ErrorKind::TimedOut, "timeout")
}

pub fn unavailable(err: &io::Error) -> bool {
    err.kind() == ErrorKind::Unsupported
        || matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS | libc::EPERM | libc::EOPNOTSUPP)
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn connect_send_recv() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            sock.write_all(b"pong").unwrap();
        });
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut sock = UringSock::connect(
            addr,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(2),
        )
        .expect("io_uring connect");
        sock.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        sock.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[test]
    fn refused_is_a_connect_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let err = match UringSock::connect(
            addr,
            Duration::from_secs(1),
            Instant::now() + Duration::from_secs(1),
        ) {
            Ok(_) => panic!("refused port accepted the connection"),
            Err(err) => err,
        };
        assert!(!unavailable(&err), "{err}");
    }
}
