use core::time;
use mio::net::{TcpStream, UdpSocket};
use quiche::Connection;
use std::{
    cmp::min, collections::HashMap, f32::consts::E, io::{self, Read, Write}
};

pub struct PartialResponse {
    pub body: Vec<u8>,

    pub written: usize,
}

pub struct Client {
    pub conn: quiche::Connection,
    pub streamId_tcpStream: HashMap<u64, mio::net::TcpStream>,
    pub token_streamId: HashMap<mio::Token, u64>,
    pub quic_partial_responses: HashMap<u64, PartialResponse>, // already read from a TCP stream, but QUIC stream_send() can't accept more data.
    pub tcp_partial_responses: HashMap<u64, PartialResponse>, // Already read from a quic stream_recv(), but TCP can't accept more data.
}

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

pub fn tcp_quic(client: &mut Client, stream_id: &u64) -> io::Result<bool> {
    debug!("TCP -> QUIC");
    // let is_ok = handle_writable(client, *stream_id);
    // if !is_ok {
    //     return Ok(false);
    // }
    let mut is_done = false;
    let mut buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    let Some(tcp_stream) = client.streamId_tcpStream.get_mut(stream_id) else {
        error!("can't find tcp steam for stream id{}", stream_id);
        return Ok(is_done);
    };

    'read: loop {
        let Ok(capacity) = client.conn.stream_capacity(*stream_id) else {
             debug!(
                "quic stream_capacity: None, is stream established? {}",
                client.conn.is_established()
            );
            return Ok(is_done);
        };
        debug!("quic stream_capacity: {capacity}");
        if capacity == 0 {
            return Ok(is_done);
        }
        let read_capacity=min(capacity,MAX_DATAGRAM_SIZE);
        let tcp_read_len = match tcp_stream.read(&mut buf[..read_capacity]) {
            Ok(0) => {
                debug!("TCP Socket closed.");
                is_done = true;
                0
            }
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
        debug!("tcp recv len:{tcp_read_len}");
        // if let Ok(str_buf) = std::str::from_utf8(&buf[..tcp_read_len]) {
        //     debug!("Received data: {}", str_buf.trim_end());
        // } else {
        //     debug!("Received (none UTF-8) data len: {}", tcp_read_len);
        // }
        if client.conn.is_established() {
            debug!("send TCP data to a quic stream");
            // TCP->QUIC
            match client
                .conn
                .stream_send(*stream_id, &buf[..tcp_read_len], is_done)
            {
                Ok(written) => {
                    if written < tcp_read_len {
                        let body: Vec<u8> = buf[..tcp_read_len].to_vec();
                        let response = PartialResponse { body, written };
                        client.quic_partial_responses.insert(*stream_id, response);
                        break 'read;
                    } else {
                        println!(
                            "Successfully sent {} bytes on stream {}",
                            written, stream_id
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

pub fn quic_tcp(client: &mut Client, stream_id: &u64) -> io::Result<bool> {
    debug!("QUIC -> TCP");
    let is_ok = handle_tcp_writable(client, stream_id);
    if !is_ok {
        return Ok(false);
    }

    let Some(tcp_stream) = client.streamId_tcpStream.get_mut(stream_id) else {
        error!("can't find tcp steam for stream id{}", stream_id);
        return Ok(false);
    };
    let mut buf = [0; 65535];
    let fin = false;
    // We can (maybe) write to the connection.
    // Process one readable streams.
    'recv: loop {
        let (read, fin) = match client.conn.stream_recv(*stream_id, &mut buf) {
            Ok(v) => v,
            Err(e) => {
                error!("{} quic recv failed: {:?}", client.conn.trace_id(), e);
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
        // if let Ok(str_buf) = std::str::from_utf8(&stream_buf) {
        //     debug!("TCP write data: {}", str_buf.trim_end());
        // } else {
            debug!("TCP write (none UTF-8) data len: {}", read);
        // }
        match tcp_stream.write(stream_buf) {
            // We want to write the entire `DATA` buffer in a single go. If we
            // write less we'll return a short write error (same as
            // `io::Write::write_all` does).
            Ok(written) => {
                if written < read {
                    let body: Vec<u8> = stream_buf.to_vec();
                    let response = PartialResponse { body, written };
                    client.tcp_partial_responses.insert(*stream_id, response);
                    break 'recv;
                } else {
                    debug!("TCP wrote {} bytes", written);
                }
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

pub fn handle_tcp_writable(client: &mut Client, stream_id: &u64) -> bool {
    debug!("handle TCP stream {} is writable", stream_id);

    if !client.tcp_partial_responses.contains_key(&stream_id) {
        return true;
    }
    let Some(tcp_stream) = client.streamId_tcpStream.get_mut(&stream_id) else {
        error!("can't find tcp steam for stream id{}", stream_id);
        return true;
    };

    let resp = client.tcp_partial_responses.get_mut(&stream_id).unwrap();
    let body = &resp.body[resp.written..];

    match tcp_stream.write(body) {
        // We want to write the entire `DATA` buffer in a single go. If we
        // write less we'll return a short write error (same as
        // `io::Write::write_all` does).
        Ok(written) => {
            resp.written += written;

            if resp.written == resp.body.len() {
                client.quic_partial_responses.remove(&stream_id);
            }
            return true;
        }
        // Would block "errors" are the OS's way of saying that the
        // connection is not actually ready to perform this I/O operation.
        Err(ref err) if would_block(err) => {
            debug!("TCP error would block {err}");
        }
        // Got interrupted (how rude!), we'll try again.
        Err(ref err) if interrupted(err) => {
            debug!("interrupted");
        }
        // Other errors we'll consider fatal.
        Err(err) => {
            error!("tcp write() failed: {:?}", err);
        }
    };
    return false;
}
/// Handles newly writable streams.
pub fn handle_writable(client: &mut Client, stream_id: u64) -> bool {
    let conn = &mut client.conn;

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !client.quic_partial_responses.contains_key(&stream_id) {
        return true;
    }

    let resp = client.quic_partial_responses.get_mut(&stream_id).unwrap();
    let body = &resp.body[resp.written..];

    let written = match conn.stream_send(stream_id, body, false) {
        Ok(v) => v,

        Err(quiche::Error::Done) => 0,

        Err(e) => {
            client.quic_partial_responses.remove(&stream_id);

            error!(
                "{} handle_writable stream send failed {:?}",
                conn.trace_id(),
                e
            );
            return false;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.quic_partial_responses.remove(&stream_id);
        return true;
    }
    return false;
}
