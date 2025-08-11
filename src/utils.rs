use mio::net::{TcpStream, UdpSocket};
use quiche::Connection;
use std::{
    f32::consts::E,
    io::{self, Read, Write},
};

pub const MAX_DATAGRAM_SIZE: usize = 1350;
// Setup some tokens to allow us to identify which event is for which socket.
pub const TCP_TOKEN: mio::Token = mio::Token(0);
pub const UDP_TOKEN: mio::Token = mio::Token(1);
pub fn get_quic_basic_config() -> quiche::Config {
    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config
        .set_application_protos(&[b"hq-interop", b"hq-29", b"hq-28", b"hq-27", b"http/0.9"])
        .unwrap();

    // config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config
}

pub fn tcp_quic(
    tcp_stream: &mut mio::net::TcpStream,
    quic_connection: &mut Connection,
    stream_id: &u64,
) -> io::Result<bool> {
    debug!("TCP -> QUIC");
    let mut connection_closed = false;
    let mut buf = [0; 65535];

    let remote_addr = tcp_stream.peer_addr().unwrap();
    println!("Remote address: {}", remote_addr);

    'read: loop {
        let len = match tcp_stream.read(&mut buf) {
            Ok(v) => v,
            // Would block "errors" are the OS's way of saying that the
            // connection is not actually ready to perform this I/O operation.
            Err(ref err) if would_block(err) => break 'read,
            Err(ref err) if interrupted(err) => continue,
            // Other errors we'll consider fatal.
            Err(err) => {
                debug!("tcp recv() failed: {:?}", err);
                return Err(err);
            }
        };
        // Reading 0 bytes means the other side has closed the
        // connection or is done writing, then so are we.
        connection_closed = len == 0;
        debug!("tcp recv len:{len}");
        if let Ok(str_buf) = std::str::from_utf8(&buf) {
            debug!("Received data: {}", str_buf.trim_end());
        } else {
            debug!("Received (none UTF-8) data: {:?}", buf);
        }
        if quic_connection.is_established() {
            debug!("send TCP data to a quic stream");
            // TCP->QUIC
            quic_connection
                .stream_send(*stream_id, &buf[..len], connection_closed)
                .unwrap();
        } else {
            error!("quic connection is not established");
            break;
        }
        if connection_closed { break };
    }
    Ok(connection_closed)
}

/// Returns `true` if the connection is done.
pub fn quic_udp(quic_connection: &mut Connection, udp_socket: &UdpSocket) -> io::Result<bool> {
    debug!("quic->udp:flush quiche connection data to udp socket");
    // Generate outgoing QUIC packets and send them on the UDP socket, until
    // quiche reports that there are no more packets to be sent.
    let mut out = [0; MAX_DATAGRAM_SIZE];
    loop {
        let (write, send_info) = match quic_connection.send(&mut out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => {
                debug!("done writing");
                break;
            }

            Err(e) => {
                error!("send failed: {:?}", e);
                quic_connection.close(false, 0x1, b"fail").ok();
                break;
            }
        };

        if let Err(e) = udp_socket.send_to(&out[..write], send_info.to) {
            if would_block(&e) {
                debug!("send() would block");
                break;
            }

            error!("send() failed: {:?}", e);
            return Err(e);
        }

        debug!("written {}", write);
    }
    if quic_connection.is_closed() {
        info!("connection closed, {:?}", quic_connection.stats());
        return Ok(true);
    }
    Ok(false)
}

/// Returns `true` if the connection is done.
pub fn udp_quic(quic_connection: &mut Connection, udp_socket: &UdpSocket) -> io::Result<bool> {
    debug!("udp -> quic");
    let mut buf = [0; 65535];
    'read: loop {
        let (len, from) = match udp_socket.recv_from(&mut buf) {
            Ok(v) => v,

            Err(e) => {
                // There are no more UDP packets to read, so end the read
                // loop.
                if would_block(&e) {
                    debug!("recv() would block");
                    break 'read;
                }
                error!("recv() failed: {:?}", e);
                return Err(e);
            }
        };

        debug!("got {} bytes", len);

        let recv_info = quiche::RecvInfo {
            to: udp_socket.local_addr().unwrap(),
            from,
        };

        // Process potentially coalesced packets.
        let read = match quic_connection.recv(&mut buf[..len], recv_info) {
            Ok(v) => v,
            Err(e) => {
                error!("recv failed: {:?}", e);
                continue 'read;
            }
        };

        debug!("processed {} bytes", read);
    }

    debug!("done reading");

    if quic_connection.is_closed() {
        info!("connection closed, {:?}", quic_connection.stats());
        return Ok(true);
    }
    Ok(false)
}

pub fn quic_tcp(
    tcp_stream: &mut mio::net::TcpStream,
    quic_connection: &mut Connection,
    stream_id: &u64,
) -> io::Result<bool> {
    debug!("QUIC -> TCP");
    let mut buf = [0; 65535];
    let fin = false;
    // We can (maybe) write to the connection.
    // Process all readable streams.
    'recv: loop {
        let (read, fin) = match quic_connection.stream_recv(*stream_id, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                error!("{} recv failed: {:?}", quic_connection.trace_id(), e);
                break 'recv;
            }
        };
        debug!("received {} bytes", read);

        let stream_buf = &buf[..read];

        debug!(
            "stream {} has {} bytes (fin? {})",
            stream_id,
            stream_buf.len(),
            fin
        );

        match tcp_stream.write(stream_buf) {
            // We want to write the entire `DATA` buffer in a single go. If we
            // write less we'll return a short write error (same as
            // `io::Write::write_all` does).
            Ok(n) if n < stream_buf.len() => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                debug!("wrote {} bytes", n);
            }
            // Would block "errors" are the OS's way of saying that the
            // connection is not actually ready to perform this I/O operation.
            Err(ref err) if would_block(err) => {}
            // Got interrupted (how rude!), we'll try again.
            Err(ref err) if interrupted(err) => {
                debug!("interrupted");
                break 'recv;
            }
            // Other errors we'll consider fatal.
            Err(err) => return Err(err),
        }

        // The server reported that it has no more data to send, which
        // we got the full response. Close the connection.
        if fin {
            info!("response received in , closing...");
            // Close the stream
            quic_connection.close(true, 0x00, b"kthxbye").unwrap();
            break 'recv;
        }
    }
    Ok(fin)
}

pub fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}

pub fn would_block(err: &std::io::Error) -> bool {
    debug!("would block");
    err.kind() == std::io::ErrorKind::WouldBlock
}
pub fn interrupted(err: &std::io::Error) -> bool {
    debug!("interrupted");
    err.kind() == std::io::ErrorKind::Interrupted
}

pub fn validate_ip_and_port(ip_str: &str, port_str: &str) -> Result<std::net::SocketAddr, String> {
    // First, let's try parsing the IP address.
    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(addr) => addr,
        Err(_) => return Err(String::from("Invalid IP address format")),
    };

    // Now, let's tackle the port.
    let port: u16 = match port_str.parse() {
        Ok(p) => {
            if p > 0 && p <= 65535 {
                p
            } else {
                return Err(String::from("Port number must be between 1 and 65535"));
            }
        }
        Err(err) => return Err(err.to_string()),
    };

    // If both parsing steps are successful, we can construct a SocketAddr.
    Ok(std::net::SocketAddr::new(ip, port))
}
