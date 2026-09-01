use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
                SocketAddr::V6(v6)
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
    }
}