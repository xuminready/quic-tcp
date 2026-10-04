use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_shutdown_signal(_sig: i32) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Installs OS signal handlers (`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`) to allow graceful exit.
pub fn install_shutdown_handlers() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    #[cfg(unix)]
    unsafe {
        unsafe extern "C" {
            fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
        }
        const SIGHUP: i32 = 1;
        const SIGINT: i32 = 2;
        const SIGQUIT: i32 = 3;
        const SIGTERM: i32 = 15;
        signal(SIGHUP, handle_shutdown_signal);
        signal(SIGINT, handle_shutdown_signal);
        signal(SIGQUIT, handle_shutdown_signal);
        signal(SIGTERM, handle_shutdown_signal);
    }
}

/// Returns `true` if a shutdown signal (`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`) or library stop request has been received.
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}

/// Requests a graceful shutdown of any active proxy loop or P2P handshake.
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Clears the shutdown flag before starting a new proxy session in library mode.
pub fn clear_shutdown() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
}

pub fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

pub fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

pub fn hex_dump(buf: &[u8]) -> String {
    buf.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<String>>()
        .join("")
}

pub fn next_token(current: &mut mio::Token) -> mio::Token {
    let next = current.0;
    current.0 += 1;
    mio::Token(next)
}

pub fn optimize_udp_socket(socket: &std::net::UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
}

pub fn optimize_tcp_stream(stream: &mio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = socket2::SockRef::from(stream);
    let _ = sock.set_recv_buffer_size(2 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(2 * 1024 * 1024);
}

pub fn bind_tcp_listener(addr: SocketAddr) -> io::Result<mio::net::TcpListener> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(mio::net::TcpListener::from_std(std_listener))
}

pub fn next_stream_id(current: &mut u64) -> u64 {
    const MAX_STREAM_ID: u64 = (1 << 62) - 1;
    if *current == 0 {
        *current = 4;
    }
    if *current > MAX_STREAM_ID - 4 {
        log::warn!("Stream ID space exhausted. Resetting to 4.");
        *current = 4;
    }
    let next = *current;
    *current += 4;
    next
}

/// Normalizes a SocketAddr, converting IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`)
/// to their canonical native IPv4 representation (`a.b.c.d`).
pub fn normalize_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            let octets = v6.ip().octets();
            // Check if it's an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
            if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            } else {
                let is_link_local = octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80;
                let scope_id = if is_link_local { v6.scope_id() } else { 0 };
                SocketAddr::V6(std::net::SocketAddrV6::new(
                    *v6.ip(),
                    v6.port(),
                    0,
                    scope_id,
                ))
            }
        }
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dump() {
        assert_eq!(hex_dump(&[0x01, 0x02, 0x0f, 0x10, 0xff]), "01020f10ff");
        assert_eq!(hex_dump(&[]), "");
    }

    #[test]
    fn test_next_token() {
        let mut token = mio::Token(10);
        assert_eq!(next_token(&mut token), mio::Token(10));
        assert_eq!(next_token(&mut token), mio::Token(11));
        assert_eq!(token, mio::Token(12));
    }

    #[test]
    fn test_next_stream_id() {
        let mut id = 0;
        assert_eq!(next_stream_id(&mut id), 4);
        assert_eq!(next_stream_id(&mut id), 8);

        let mut limit_id = ((1 << 62) - 1) - 2;
        // Since limit_id > MAX_STREAM_ID - 4, this call resets it to 4 and returns 4
        assert_eq!(next_stream_id(&mut limit_id), 4);
        // The subsequent call returns 8
        assert_eq!(next_stream_id(&mut limit_id), 8);
    }

    #[test]
    fn test_normalize_socket_addr() {
        // Native IPv4 remains unchanged
        let v4_addr: SocketAddr = "223.73.209.117:5759".parse().unwrap();
        assert_eq!(normalize_socket_addr(v4_addr), v4_addr);

        // IPv4-mapped IPv6 is converted to canonical IPv4
        let mapped_addr: SocketAddr = "[::ffff:223.73.209.117]:5759".parse().unwrap();
        assert_eq!(normalize_socket_addr(mapped_addr), v4_addr);

        // Native IPv6 remains unchanged
        let v6_addr: SocketAddr = "[2001:db8::1]:5759".parse().unwrap();
        assert_eq!(normalize_socket_addr(v6_addr), v6_addr);

        // IPv6 with flowinfo set is normalized to flowinfo = 0
        let v6_flowinfo = SocketAddr::V6(std::net::SocketAddrV6::new(
            "2001:db8::1".parse().unwrap(),
            5759,
            12345,
            0,
        ));
        assert_eq!(normalize_socket_addr(v6_flowinfo), v6_addr);

        // Global IPv6 with scope_id set is normalized to scope_id = 0
        let v6_scope = SocketAddr::V6(std::net::SocketAddrV6::new(
            "2001:db8::1".parse().unwrap(),
            5759,
            0,
            2,
        ));
        assert_eq!(normalize_socket_addr(v6_scope), v6_addr);

        // Link-local IPv6 preserves its scope_id
        let link_local = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            5759,
            0,
            2,
        ));
        assert_eq!(normalize_socket_addr(link_local), link_local);
    }
}
