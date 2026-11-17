use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::uring::{self, UringSock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, SignatureScheme};

pub struct Probe {
    pub proxy: String,
    pub proxy_user: Option<String>,
    pub url: String,
    pub connect_timeout: Duration,
    pub max_time: Duration,
}

impl Probe {
    pub fn run(&self) -> String {
        match self.run_inner() {
            Ok(text) => text,
            Err(_) => "0".to_string(),
        }
    }

    fn run_inner(&self) -> std::io::Result<String> {
        let start = Instant::now();
        let budget = self.max_time;
        let (proxy_host, proxy_port) = parse_proxy(&self.proxy).ok_or(io_err("proxy"))?;
        let target = parse_target(&self.url).ok_or(io_err("url"))?;
        let addr = resolve_proxy(&proxy_host, proxy_port).ok_or(io_err("resolve"))?;
        let connect_for = self
            .connect_timeout
            .min(remaining(start, budget).ok_or(io_err("timeout"))?);
        let deadline = start + budget;
        match UringSock::connect(addr, connect_for, deadline) {
            Ok(sock) => self.finish(sock, &target, start, budget),
            Err(err) if uring::unavailable(&err) => {
                let mut tcp = TcpStream::connect_timeout(&addr, connect_for)?;
                tcp.set_nodelay(true)?;
                set_quickack(tcp.as_raw_fd());
                tcp.arm(start, budget)?;
                self.finish(tcp, &target, start, budget)
            }
            Err(err) => Err(err),
        }
    }

    fn finish<S: Sock>(
        &self,
        mut sock: S,
        target: &Target,
        start: Instant,
        budget: Duration,
    ) -> std::io::Result<String> {
        socks5(&mut sock, target, self.proxy_user.as_deref())?;
        if target.tls {
            https_probe(&mut sock, target, start, budget)
        } else {
            http_probe(&mut sock, target, start, budget)
        }
    }
}

trait Sock: Read + Write {
    fn arm(&mut self, start: Instant, budget: Duration) -> std::io::Result<()>;
}

impl Sock for UringSock {
    fn arm(&mut self, start: Instant, budget: Duration) -> std::io::Result<()> {
        self.set_deadline(start, budget)
    }
}

impl Sock for TcpStream {
    fn arm(&mut self, start: Instant, budget: Duration) -> std::io::Result<()> {
        let left = remaining(start, budget).ok_or(io_err("timeout"))?;
        self.set_read_timeout(Some(left))?;
        self.set_write_timeout(Some(left))?;
        Ok(())
    }
}

fn https_probe<S: Sock>(
    tcp: &mut S,
    target: &Target,
    start: Instant,
    budget: Duration,
) -> std::io::Result<String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = server_name(&target.host).map_err(|_| io_err("sni"))?;
    let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|_| io_err("tls"))?;
    tcp.arm(start, budget)?;
    while conn.is_handshaking() {
        tcp.arm(start, budget)?;
        conn.complete_io(tcp)?;
    }
    let pre = start.elapsed();
    let req = request_bytes(target);
    conn.writer().write_all(&req)?;
    while conn.wants_write() {
        tcp.arm(start, budget)?;
        conn.complete_io(tcp)?;
    }
    let (code, start_at) = read_tls_status(&mut conn, tcp, start, budget)?;
    Ok(timing(code, pre, start_at))
}

fn http_probe<S: Sock>(
    tcp: &mut S,
    target: &Target,
    start: Instant,
    budget: Duration,
) -> std::io::Result<String> {
    let pre = start.elapsed();
    tcp.arm(start, budget)?;
    tcp.write_all(&request_bytes(target))?;
    let (code, start_at) = read_status(tcp, start, budget)?;
    Ok(timing(code, pre, start_at))
}

fn request_bytes(target: &Target) -> Vec<u8> {
    format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: curl/8.12.1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.path, target.host_header
    )
    .into_bytes()
}

fn timing(code: u16, pre: Duration, start_at: Duration) -> String {
    format!(
        "{code}:{:.6}:{:.6}",
        pre.as_secs_f64(),
        start_at.as_secs_f64()
    )
}

fn read_status<S: Sock>(
    tcp: &mut S,
    start: Instant,
    budget: Duration,
) -> std::io::Result<(u16, Duration)> {
    let mut buf = [0u8; 256];
    let mut filled = 0;
    let mut start_at = None;
    while filled < buf.len() && !buf[..filled].contains(&b'\n') {
        tcp.arm(start, budget)?;
        let n = tcp.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        if start_at.is_none() {
            start_at = Some(start.elapsed());
        }
        filled += n;
    }
    let start_at = start_at.ok_or(io_err("eof"))?;
    let code = status_code(&buf[..filled]).ok_or(io_err("status"))?;
    Ok((code, start_at))
}

fn read_tls_status<S: Sock>(
    conn: &mut ClientConnection,
    tcp: &mut S,
    start: Instant,
    budget: Duration,
) -> std::io::Result<(u16, Duration)> {
    let mut marked: Option<Duration> = None;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    while buf.len() < 256 && !buf.ends_with(b"\n") {
        tcp.arm(start, budget)?;
        let want = (256 - buf.len()).min(chunk.len());
        match conn.reader().read(&mut chunk[..want]) {
            Ok(0) => {
                if conn.is_handshaking() || conn.wants_read() {
                    conn.complete_io(tcp)?;
                    continue;
                }
                break;
            }
            Ok(n) => {
                if marked.is_none() {
                    marked = Some(start.elapsed());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                conn.complete_io(tcp)?;
            }
            Err(err) => return Err(err),
        }
    }
    let code = status_code(&buf).ok_or(io_err("status"))?;
    Ok((code, marked.ok_or(io_err("eof"))?))
}

fn status_code(buf: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(buf).ok()?.trim();
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

fn socks5<S: Read + Write>(
    tcp: &mut S,
    target: &Target,
    user: Option<&str>,
) -> std::io::Result<()> {
    if let Some(user) = user {
        let (name, pass) = split_user(user);
        tcp.write_all(&[0x05, 0x02, 0x00, 0x02])?;
        let mut method = [0u8; 2];
        tcp.read_exact(&mut method)?;
        if method != [0x05, 0x02] && method != [0x05, 0x00] {
            return Err(io_err("socks method"));
        }
        if method[1] == 0x02 {
            if name.len() > 255 || pass.len() > 255 {
                return Err(io_err("socks auth"));
            }
            let mut req = vec![0x01, name.len() as u8];
            req.extend_from_slice(name.as_bytes());
            req.push(pass.len() as u8);
            req.extend_from_slice(pass.as_bytes());
            tcp.write_all(&req)?;
            let mut ans = [0u8; 2];
            tcp.read_exact(&mut ans)?;
            if ans != [0x01, 0x00] {
                return Err(io_err("socks auth"));
            }
        }
    } else {
        tcp.write_all(&[0x05, 0x01, 0x00])?;
        let mut method = [0u8; 2];
        tcp.read_exact(&mut method)?;
        if method != [0x05, 0x00] {
            return Err(io_err("socks method"));
        }
    }
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                req.push(0x01);
                req.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                req.push(0x04);
                req.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if target.host.len() > 255 {
            return Err(io_err("host"));
        }
        req.push(0x03);
        req.push(target.host.len() as u8);
        req.extend_from_slice(target.host.as_bytes());
    }
    req.extend_from_slice(&target.port.to_be_bytes());
    tcp.write_all(&req)?;
    let mut hdr = [0u8; 4];
    tcp.read_exact(&mut hdr)?;
    if hdr[1] != 0x00 {
        return Err(io_err("socks connect"));
    }
    match hdr[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            tcp.read_exact(&mut rest)?;
        }
        0x04 => {
            let mut rest = [0u8; 18];
            tcp.read_exact(&mut rest)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len)?;
            let mut rest = vec![0u8; len[0] as usize + 2];
            tcp.read_exact(&mut rest)?;
        }
        _ => return Err(io_err("socks atyp")),
    }
    Ok(())
}

struct Target {
    tls: bool,
    host: String,
    port: u16,
    path: String,
    host_header: String,
}

fn parse_target(url: &str) -> Option<Target> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return None;
    };
    if rest.is_empty() {
        return None;
    }
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'?' => (&rest[..i], format!("/{}", &rest[i..])),
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = split_host_port(authority, if tls { 443 } else { 80 })?;
    let host_header = if (tls && port == 443) || (!tls && port == 80) {
        if host.contains(':') {
            format!("[{host}]")
        } else {
            host.clone()
        }
    } else if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Some(Target {
        tls,
        host,
        port,
        path,
        host_header,
    })
}

fn parse_proxy(proxy: &str) -> Option<(String, u16)> {
    let rest = proxy
        .strip_prefix("socks5h://")
        .or_else(|| proxy.strip_prefix("socks5://"))?;
    let rest = match rest.rfind('@') {
        Some(at) => &rest[at + 1..],
        None => rest,
    };
    split_host_port(rest, 1080)
}

fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = if let Some(port) = after.strip_prefix(':') {
            port.parse().ok()?
        } else if after.is_empty() {
            default_port
        } else {
            return None;
        };
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) => {
            Some((host.to_string(), port.parse().ok()?))
        }
        _ => Some((authority.to_string(), default_port)),
    }
}

fn split_user(user: &str) -> (&str, &str) {
    match user.split_once(':') {
        Some((name, pass)) => (name, pass),
        None => (user, ""),
    }
}

fn resolve_proxy(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    let mut addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host, port)).ok()?;
    addrs.next()
}

fn server_name(host: &str) -> Result<ServerName<'static>, ()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        ServerName::try_from(host.to_string()).map_err(|_| ())
    }
}

fn remaining(start: Instant, budget: Duration) -> Option<Duration> {
    budget
        .checked_sub(start.elapsed())
        .filter(|left| !left.is_zero())
}

fn set_quickack(fd: i32) {
    let one: i32 = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_QUICKACK,
            &one as *const i32 as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        );
    }
}

fn io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn socks_http_204() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).unwrap();
            sock.write_all(&[0x05, 0x00]).unwrap();
            let mut hdr = [0u8; 4];
            sock.read_exact(&mut hdr).unwrap();
            assert_eq!(hdr[3], 0x03);
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).unwrap();
            let mut rest = vec![0u8; len[0] as usize + 2];
            sock.read_exact(&mut rest).unwrap();
            let host = &rest[..len[0] as usize];
            assert_eq!(host, b"example.com");
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            let mut req = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = sock.read(&mut tmp).unwrap();
                req.extend_from_slice(&tmp[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(req.starts_with(b"HEAD /generate_204 HTTP/1.1\r\n"));
            sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let text = Probe {
            proxy: format!("socks5h://127.0.0.1:{port}"),
            proxy_user: None,
            url: "http://example.com/generate_204".into(),
            connect_timeout: Duration::from_secs(2),
            max_time: Duration::from_secs(2),
        }
        .run();
        assert!(text.starts_with("204:"), "{text}");
        let mut parts = text.split(':');
        let _code = parts.next().unwrap();
        let pre: f64 = parts.next().unwrap().parse().unwrap();
        let start: f64 = parts.next().unwrap().parse().unwrap();
        assert!(start >= pre);
    }

    #[test]
    fn refused_proxy_is_zero() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let text = Probe {
            proxy: format!("socks5h://127.0.0.1:{port}"),
            proxy_user: None,
            url: "https://example.com/".into(),
            connect_timeout: Duration::from_millis(200),
            max_time: Duration::from_millis(500),
        }
        .run();
        assert_eq!(text, "0");
    }
}
