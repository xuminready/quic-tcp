use quiche::Connection;
use mio::net::{TcpStream, UdpSocket};
use ring::rand::*;
use std::io::{self, Read, Write};


const MAX_DATAGRAM_SIZE: usize = 1350;
pub fn create_quic_connection(
    server_name: Option<&str>,
    peer_addr: &std::net::SocketAddr,
    socket: &UdpSocket,
) -> Connection {
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

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Get local address.
    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let conn = quiche::connect(server_name, &scid, local_addr, *peer_addr, &mut config).unwrap();

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    conn
}

pub fn tcp_quic(
    tcp_stream: &mut mio::net::TcpStream,
    quic_connection: &mut Connection,
    stream_id: &u64,
) {
    debug!("TCP -> QUIC");
    let mut connection_closed = false;
    let mut buf = [0; 65535];

    let remote_addr = tcp_stream.peer_addr().unwrap();
    println!("Remote address: {}", remote_addr);

    loop {
        match tcp_stream.read(&mut buf) {
            Ok(0) => {
                // Reading 0 bytes means the other side has closed the
                // connection or is done writing, then so are we.
                connection_closed = true;
                break;
            }
            Ok(n) => {
                if let Ok(str_buf) = std::str::from_utf8(&buf) {
                    debug!("Received data: {}", str_buf.trim_end());
                } else {
                    debug!("Received (none UTF-8) data: {:?}", buf);
                }
                if quic_connection.is_established() {
                    debug!("send TCP data to a quic stream");
                    // TCP->QUIC
                    quic_connection
                        .stream_send(*stream_id, &buf[..n], false)
                        .unwrap();
                }else{
                    error!("quic connection is not established");
                    break;
                }
            }
            // Would block "errors" are the OS's way of saying that the
            // connection is not actually ready to perform this I/O operation.
            Err(ref err) if would_block(err) => break,
            Err(ref err) if interrupted(err) => continue,
            // Other errors we'll consider fatal.
            Err(err) => {
                debug!("tcp recv() failed: {:?}", err);
                return;
            }
        }
    }


}

pub fn quic_udp(quic_connection: &mut Connection, udp_socket: &UdpSocket) {
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
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send() would block");
                break;
            }

            panic!("send() failed: {:?}", e);
        }

        debug!("written {}", write);
    }
    if quic_connection.is_closed() {
        info!("connection closed, {:?}", quic_connection.stats());
        return;
    }
}

pub fn udp_quic(quic_connection: &mut Connection, udp_socket: &UdpSocket){
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
                panic!("recv() failed: {:?}", e);
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
        return;
    }
}

pub fn quic_tcp(    
    tcp_stream: &mut mio::net::TcpStream,
    quic_connection: &mut Connection,
    stream_id: &u64,){
    debug!("QUIC -> TCP");
    let mut buf = [0; 65535];
// We can (maybe) write to the connection.
    // Process all readable streams.
    for stream_id in quic_connection.readable() {
        while let Ok((read, fin)) = quic_connection.stream_recv(stream_id, &mut buf) {
            debug!("received {} bytes", read);

            let stream_buf = &buf[..read];

            debug!(
                "stream {} has {} bytes (fin? {})",
                stream_id,
                stream_buf.len(),
                fin
            );
            print!("{}", unsafe { std::str::from_utf8_unchecked(stream_buf) });
            match tcp_stream.write(stream_buf) {
                // We want to write the entire `DATA` buffer in a single go. If we
                // write less we'll return a short write error (same as
                // `io::Write::write_all` does).
                Ok(n) if n < stream_buf.len() => {
                    return; //Err(std::io::ErrorKind::WriteZero.into())
                }
                Ok(_) => {
                    // After we've written something we'll reregister the connection
                    // to only respond to readable events.
                    // registry.reregister(connection, event.token(), mio::Interest::READABLE)?
                }
                // Would block "errors" are the OS's way of saying that the
                // connection is not actually ready to perform this I/O operation.
                Err(ref err) if would_block(err) => {}
                // Got interrupted (how rude!), we'll try again.
                Err(ref err) if interrupted(err) => {
                    debug!("interrupted");
                    //TODO do we really need to re-try?
                    return quic_tcp(
                        tcp_stream,
                        quic_connection,
                        &stream_id,
                    )
                }
                // Other errors we'll consider fatal.
                Err(err) => return, //Err(err),
            }

            // The server reported that it has no more data to send, which
            // we got the full response. Close the connection.
            if fin {
                info!("response received in , closing...");
                // Close the stream
                // quic_connection.close(true, 0x00, b"kthxbye").unwrap();
            }
        }
    }
}
pub fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}

pub fn would_block(err: &std::io::Error) -> bool {
    debug!("recv() would block");
    err.kind() == std::io::ErrorKind::WouldBlock
}
pub fn interrupted(err: &std::io::Error) -> bool {
    debug!("interrupted");
    err.kind() == std::io::ErrorKind::Interrupted
}
