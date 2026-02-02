use core::time;
use mio::net::{TcpStream, UdpSocket};
use quiche::Connection;
use std::{
    collections::HashMap,
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
    udp_socket: &UdpSocket,
) -> io::Result<bool> {
    debug!("TCP -> QUIC");
    let mut is_done = false;
    let mut buf = [0; 13500];

    'read: loop {
        if let Ok(capacity) = quic_connection.stream_capacity(*stream_id) {
            debug!("quic stream_capacity: {}", capacity);
            if capacity < 13500 {
                //TODO improve when the steam capacity is smaller than buf size.
                break;
            }
        } else {
            debug!(
                "quic stream_capacity: None, is stream established? {}",
                quic_connection.is_established()
            );
        }
        let len = match tcp_stream.read(&mut buf) {
            Ok(0) => {
                debug!("TCP Socket closed.");
                is_done = true;
                0
            },
            Ok(v) => v,
            // Would block "errors" are the OS's way of saying that the
            // connection is not actually ready to perform this I/O operation.
            Err(ref err) if would_block(err) => break 'read,
            Err(ref err) if interrupted(err) => continue,
            // Other errors we'll consider fatal.
            Err(err) => {
                error!("tcp read() failed: {:?}", err);
                continue;
            }
        };
        // Reading 0 bytes means the other side has closed the
        // connection or is done writing, then so are we.
        debug!("tcp recv len:{len}");
        if let Ok(str_buf) = std::str::from_utf8(&buf) {
            debug!("Received data: {}", str_buf.trim_end());
        } else {
            debug!("Received (none UTF-8) data len: {}", len);
        }
        if quic_connection.is_established() {
            debug!("send TCP data to a quic stream");
            // TCP->QUIC
            match quic_connection.stream_send(*stream_id, &buf[..len], is_done) {
                Ok(quic_sent) => {
                    println!(
                        "Successfully sent {} bytes on stream {}",
                        quic_sent, stream_id
                    );
                    if quic_sent != len {
                        eprintln!(
                            "🔴🔴🔴🔴🔴🔴🔴🔴 data lost!🔴🔴🔴🔴 tcp read {len}, quic sent {quic_sent}"
                        );
                    }
                }
                Err(e) => {
                    eprintln!(
                        "🔴 ERROR: Failed to send data on stream {}: {:?}",
                        stream_id, e
                    );
                }
            }
        } else {
            error!("🔴🔴🔴quic connection is not established");
            break;
        }
        break;
        let _ = quic_udp(quic_connection, udp_socket);
        if is_done {
            debug!("connection closed");
            break;
        };
    }
    Ok(is_done)
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
                debug!("quic done writing");
                break;
            }

            Err(e) => {
                error!("quic send failed: {:?}", e);
                quic_connection.close(false, 0x1, b"fail").ok();
                break;
            }
        };

        if let Err(e) = udp_socket.send_to(&out[..write], send_info.to) {
            if would_block(&e) {
                debug!("send() would block");
                break;
            }

            error!("udp send() failed: {:?}", e);
            return Err(e);
        }

        debug!("quic_udp written {}", write);
    }
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
    // Process one readable streams.
    'recv: loop {
        let (read, fin) = match quic_connection.stream_recv(*stream_id, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                error!("{} quic recv failed: {:?}", quic_connection.trace_id(), e);
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
        if let Ok(str_buf) = std::str::from_utf8(&stream_buf) {
            debug!("TCP write data: {}", str_buf.trim_end());
        } else {
            debug!("TCP write (none UTF-8) data len: {}", read);
        }
        match tcp_stream.write(stream_buf) {
            // We want to write the entire `DATA` buffer in a single go. If we
            // write less we'll return a short write error (same as
            // `io::Write::write_all` does).
            Ok(n) if n < stream_buf.len() => {
                debug!(
                    "🔴🔴🔴🔴  TCP wrote less than expected. wrote {} of , {}",
                    n,
                    stream_buf.len()
                );
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            Ok(n) => {
                debug!("TCP wrote {} bytes", n);
            }
            // Would block "errors" are the OS's way of saying that the
            // connection is not actually ready to perform this I/O operation.
            Err(ref err) if would_block(err) => {
                debug!("TCP wrote failed, expected wrote {read} bytes, would block {err}");
                break 'recv;
            }
            // Got interrupted (how rude!), we'll try again.
            Err(ref err) if interrupted(err) => {
                debug!("interrupted");
                break 'recv;
            }
            // Other errors we'll consider fatal.
            Err(err) => {
                error!("tcp write() failed: {:?}", err);
                return Err(err);
            }
        }

        // The server reported that it has no more data to send, which
        // we got the full response. Close the connection.
        if fin {
            info!("fin response received in , closing...");
            // don't close quic_connection, only close stream
            // quic_connection.close(true, 0x00, b"kthxbye").unwrap();
            tcp_stream
                .shutdown(std::net::Shutdown::Both)
                .unwrap_or_else(|err| {
                    eprintln!("🔴🔴🔴🔴TCP shutdown error: {}", err);
                });
            println!("🔴🔴🔴🔴 close TCP stream for stream id {stream_id}");
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
