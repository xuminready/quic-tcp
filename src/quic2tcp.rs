#[macro_use]
extern crate log;

mod utils;

use std::env::Args;
use std::net;

use mio::Token;
use mio::net::{TcpStream, UdpSocket};
use quiche::Connection;
use ring::rand::*;
use std::collections::{HashMap, HashSet, hash_set};
use std::io::{self, Read, Write};
use utils::*;

struct PartialResponse {
    body: Vec<u8>,

    written: usize,
}

struct Client {
    conn: quiche::Connection,
    partial_responses: HashMap<u64, PartialResponse>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;
type ConnecId = [u8; quiche::MAX_CONN_ID_LEN];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init(); // Initialize env_logger

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <Local_UDP_(QUIC)Server_IP> <Local_Port> <Remote_TCP_IP> <Remote_Port>",
            args[0]
        );
        return Ok(());
    }
    let udp_local_ip_str = &args[1];
    let udp_local_port_str = &args[2];
    let tcp_remote_ip_str = &args[3];
    let tcp_remote_port_str = &args[4];

    println!("UDP Local  Server: {udp_local_ip_str}:{udp_local_port_str}");
    println!("TCP Remote Server: {tcp_remote_ip_str}:{tcp_remote_port_str}");

    let udp_local_addr = validate_ip_and_port(udp_local_ip_str, udp_local_port_str)?;
    let tcp_remote_addr = validate_ip_and_port(tcp_remote_ip_str, tcp_remote_port_str)?;

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);
    // Create the UDP listening socket, and register it with the event loop.
    let mut udp_socket = mio::net::UdpSocket::bind(udp_local_addr).unwrap();
    poll.registry()
        .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = get_quic_basic_config();
    config.load_cert_chain_from_pem_file("cert.crt").unwrap();
    config.load_priv_key_from_pem_file("cert.key").unwrap();
    config.enable_early_data();
    let rng: SystemRandom = SystemRandom::new();
    let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();

    let local_addr = udp_socket.local_addr().unwrap();
    // Unique token for each incoming connection.
    let mut streamId_tcp_stream_map: HashMap<u64, mio::net::TcpStream> = HashMap::new();
    let mut token_streamId_map = HashMap::new();
    let mut token_scid_map: HashMap<mio::Token, quiche::ConnectionId> = HashMap::new();

    let mut buf = [0; 65535];
    // Unique token for each incoming connection.
    let mut unique_token: mio::Token = mio::Token(UDP_TOKEN.0 + 1);
    let mut unfinished_stream_ids = HashSet::new();

    loop {
        // Find the shorter timeout from all the active connections.
        //
        // TODO: use event loop that properly supports timers
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();
        poll.poll(&mut events, timeout).unwrap();
        for event in events.iter() {
            match event.token() {
                TCP_TOKEN => {
                    error!("TCP token");
                } // not used for quic server.
                UDP_TOKEN => {
                    error!("UDP token");
                    // Read incoming UDP packets from the socket and feed them to quiche,
                    // until there are no more packets to read.
                    'read: loop {
                        // If the event loop reported no events, it means that the timeout
                        // has expired, so handle it without attempting to read packets. We
                        // will then proceed with the send loop.
                        if events.is_empty() {
                            debug!("timed out");

                            clients.values_mut().for_each(|c| c.conn.on_timeout());

                            break 'read;
                        }

                        let (len, from) = match udp_socket.recv_from(&mut buf) {
                            Ok(v) => v,

                            Err(e) => {
                                // There are no more UDP packets to read, so end the read
                                // loop.
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    debug!("recv() would block");
                                    break 'read;
                                }

                                panic!("recv() failed: {:?}", e);
                            }
                        };

                        debug!("got {} bytes", len);

                        let pkt_buf = &mut buf[..len];

                        // Parse the QUIC packet's header.
                        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN)
                        {
                            Ok(v) => v,

                            Err(e) => {
                                error!("Parsing packet header failed: {:?}", e);
                                continue 'read;
                            }
                        };

                        trace!("got packet {:?}", hdr);

                        let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                        let conn_id = conn_id.to_vec().into();

                        // Lookup a connection based on the packet's connection ID. If there
                        // is no connection matching, create a new one.
                        let client = if !clients.contains_key(&hdr.dcid)
                            && !clients.contains_key(&conn_id)
                        {
                            if hdr.ty != quiche::Type::Initial {
                                error!("Packet is not Initial");
                                continue 'read;
                            }

                            let mut out = [0; MAX_DATAGRAM_SIZE];
                            if !quiche::version_is_supported(hdr.version) {
                                warn!("Doing version negotiation");
                                let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                                    .unwrap();

                                let out = &out[..len];

                                if let Err(e) = udp_socket.send_to(out, from) {
                                    if e.kind() == std::io::ErrorKind::WouldBlock {
                                        debug!("send() would block");
                                        break;
                                    }

                                    panic!("send() failed: {:?}", e);
                                }
                                continue 'read;
                            }

                            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                            scid.copy_from_slice(&conn_id);

                            let scid = quiche::ConnectionId::from_ref(&scid);

                            // Token is always present in Initial packets.
                            let token = hdr.token.as_ref().unwrap();

                            // Do stateless retry if the client didn't send a token.
                            if token.is_empty() {
                                warn!("Doing stateless retry");

                                let new_token = mint_token(&hdr, &from);

                                let len = quiche::retry(
                                    &hdr.scid,
                                    &hdr.dcid,
                                    &scid,
                                    &new_token,
                                    hdr.version,
                                    &mut out,
                                )
                                .unwrap();

                                let out = &out[..len];

                                if let Err(e) = udp_socket.send_to(out, from) {
                                    if e.kind() == std::io::ErrorKind::WouldBlock {
                                        debug!("send() would block");
                                        break;
                                    }

                                    panic!("send() failed: {:?}", e);
                                }
                                continue 'read;
                            }

                            let odcid = validate_token(&from, token);

                            // The token was not valid, meaning the retry failed, so
                            // drop the packet.
                            if odcid.is_none() {
                                error!("Invalid address validation token");
                                continue 'read;
                            }

                            if scid.len() != hdr.dcid.len() {
                                error!("Invalid destination connection ID");
                                continue 'read;
                            }

                            // Reuse the source connection ID we sent in the Retry packet,
                            // instead of changing it again.
                            let scid = hdr.dcid.clone();

                            debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                            let conn = quiche::accept(
                                &scid,
                                odcid.as_ref(),
                                local_addr,
                                from,
                                &mut config,
                            )
                            .unwrap();
                            let client = Client {
                                conn,
                                partial_responses: HashMap::new(),
                            };

                            assert_eq!(scid, client.conn.source_id());
                            clients.insert(scid.clone(), client);

                            clients.get_mut(&scid).unwrap()
                        } else {
                            match clients.get_mut(&hdr.dcid) {
                                Some(v) => v,

                                None => clients.get_mut(&conn_id).unwrap(),
                            }
                        };

                        let recv_info = quiche::RecvInfo {
                            to: udp_socket.local_addr().unwrap(),
                            from,
                        };

                        // Process potentially coalesced packets.
                        let read = match client.conn.recv(pkt_buf, recv_info) {
                            Ok(v) => v,

                            Err(e) => {
                                error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                                continue 'read;
                            }
                        };

                        debug!("{} processed {} bytes", client.conn.trace_id(), read);

                        if client.conn.is_in_early_data() || client.conn.is_established() {
                            // Handle writable streams.
                            for stream_id in client.conn.writable() {
                                handle_writable(client, stream_id);

                                if let Some(tcp_stream) =
                                    streamId_tcp_stream_map.get_mut(&stream_id)
                                    && unfinished_stream_ids.contains(&stream_id)
                                {
                                    if let Ok(is_done) = tcp_quic(
                                        tcp_stream,
                                        &mut client.conn,
                                        &stream_id,
                                        &udp_socket,
                                    ) {
                                        if is_done {
                                            unfinished_stream_ids.remove(&stream_id);
                                        }
                                    }
                                }
                            }
                            // Process all readable streams.
                            for stream_id in client.conn.readable() {
                                // create a new TCP stream if it's not exist for a stream_id
                                if !streamId_tcp_stream_map.contains_key(&stream_id) {
                                    let token = next(&mut unique_token);
                                    // Setup the new client socket.
                                    let mut tcp_stream =
                                        mio::net::TcpStream::connect(tcp_remote_addr).unwrap();
                                    poll.registry()
                                        .register(&mut tcp_stream, token, mio::Interest::READABLE)
                                        .unwrap();
                                    streamId_tcp_stream_map.insert(stream_id.clone(), tcp_stream);
                                    token_streamId_map.insert(token.clone(), stream_id.clone());
                                    let scid = quiche::ConnectionId::from_vec(
                                        client.conn.source_id().as_ref().to_vec(),
                                    );
                                    // let cid_slice = scid.as_ref(); // Get the underlying byte slice
                                    // let mut fixed_size_array: ConnecId = [0; quiche::MAX_CONN_ID_LEN];
                                    // fixed_size_array[..cid_slice.len()].copy_from_slice(cid_slice);
                                    token_scid_map.insert(token.clone(), scid);
                                }
                                if let Some(mut tcp_stream) =
                                    streamId_tcp_stream_map.get_mut(&stream_id)
                                {
                                    quic_tcp(tcp_stream, &mut client.conn, &stream_id);
                                }
                            }
                            debug!("Done for handle stream!!!");
                        }
                    }
                }
                token => {
                    error!("TCP client Token");
                    // received an event for a TCP connection.
                    let done = if let Some(stream_id) = token_streamId_map.get_mut(&token) {
                        let mut is_tcp_stream_closed = false;
                        let mut tcp_stream = streamId_tcp_stream_map.get_mut(&stream_id).unwrap();
                        // let cid_slice: &mut [u8; 20] = token_scid_map.get_mut(&token).unwrap();

                        // let cid_slice: [u8; quiche::MAX_CONN_ID_LEN] = [0; quiche::MAX_CONN_ID_LEN];
                        // let scid = quiche::ConnectionId::from_vec(cid_slice.to_vec());
                        let scid = token_scid_map.get(&token).unwrap();
                        let mut client = clients.get_mut(&scid).unwrap();

                        if let Ok(is_done) =
                            tcp_quic(&mut tcp_stream, &mut client.conn, stream_id, &udp_socket)
                        {
                            if is_done {
                                unfinished_stream_ids.remove(stream_id);
                            } else {
                                unfinished_stream_ids.insert(stream_id.clone());
                            }
                        }
                        false
                        //TODO return the TCP connection status remove disconnection and update hashmap
                    } else {
                        // Sporadic events happen, we can safely ignore them.
                        false
                    };
                    if done {
                        debug!("done, close tcp stream");
                        // remove from the hashmap
                        // if let Some(stream_id) = token_streamId_map.remove(&token) {
                        //     streamId_token_map.remove(&stream_id);
                        // }
                        // if let Some(mut tcp_stream) = token_tcp_stream_map.remove(&token) {
                        //     poll.registry().deregister(&mut tcp_stream)?;
                        // }
                    }
                }
            }

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            for client in clients.values_mut() {
                // flush the data to UDP socket
                let _ = quic_udp(&mut client.conn, &udp_socket);
            }

            // Garbage collect closed connections.
            clients.retain(|_, ref mut c| {
                debug!("Collecting garbage");

                if c.conn.is_closed() {
                    info!(
                        "{} connection collected {:?}",
                        c.conn.trace_id(),
                        c.conn.stats()
                    );
                }

                !c.conn.is_closed()
            });
        }
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(src: &net::SocketAddr, token: &'a [u8]) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

/// Handles incoming HTTP/0.9 requests.
fn handle_stream(
    client: &mut Client,
    stream_id: u64,
    mut buf: &[u8],
    streamId_tcp_stream_map: &mut HashMap<u64, mio::net::TcpStream>,
) {
    let conn = &mut client.conn;
    if let Ok(str_buf) = std::str::from_utf8(buf) {
        println!("Received data: {}", str_buf.trim_end());
    } else {
        println!("Received (none UTF-8) data: {:?}", buf);
    }
    if buf.len() > 0 {
        if !streamId_tcp_stream_map.contains_key(&stream_id) {
            // let token = next(unique_token);
            // Setup the new client socket.
            let addr_str = "127.0.0.1:8000";
            let addr: net::SocketAddr = addr_str.parse().unwrap();
            let tcp_stream = mio::net::TcpStream::connect(addr).unwrap();
            // poll.registry()
            //     .register(
            //         &mut tcp_stream,
            //         token,
            //         mio::Interest::READABLE,
            //     )
            //     .unwrap();
            streamId_tcp_stream_map.insert(stream_id.clone(), tcp_stream);
        }

        //TODO  received buff is too small, It may require mutiple read
        let mut received_data = vec![0; 4096];
        let mut bytes_read = 0;
        if let Some(mut tcp_stream) = streamId_tcp_stream_map.get_mut(&stream_id) {
            match std::io::Write::write(&mut tcp_stream, buf) {
                Ok(0) => {
                    // Reading 0 bytes means the other side has closed the
                    // connection or is done writing, then so are we.
                }
                Ok(n) => {
                    debug!("quic-> TCP {n}");
                }

                // Other errors we'll consider fatal.
                Err(err) => {
                    debug!("tcp send() failed: {:?}", err);
                    return;
                }
            }
            match std::io::Read::read(&mut tcp_stream, &mut received_data[bytes_read..]) {
                Ok(0) => {
                    // Reading 0 bytes means the other side has closed the
                    // connection or is done writing, then so are we.
                }
                Ok(n) => {
                    bytes_read += n;
                    if bytes_read == received_data.len() {
                        received_data.resize(received_data.len() + 1024, 0);
                    }
                }

                // Other errors we'll consider fatal.
                Err(err) => {
                    debug!("tcp recv() failed: {:?}", err);
                    return;
                }
            }
        } else {
        };
        let body: Vec<u8> = received_data; //= std::fs::read(path).unwrap_or_else(|_| b"Not Found!\r\n".to_vec());

        info!(
            "{} sending response of size {} on stream {}",
            conn.trace_id(),
            body.len(),
            stream_id
        );
        let written = match conn.stream_send(stream_id, &body, false) {
            Ok(v) => v,

            Err(quiche::Error::Done) => 0,

            Err(e) => {
                error!(
                    "{} handle_stream stream send failed {:?}",
                    conn.trace_id(),
                    e
                );
                return;
            }
        };

        if written < body.len() {
            let response = PartialResponse { body, written };
            client.partial_responses.insert(stream_id, response);
        }
    }
}

/// Handles newly writable streams.
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();
    let body = &resp.body[resp.written..];

    let written = match conn.stream_send(stream_id, body, false) {
        Ok(v) => v,

        Err(quiche::Error::Done) => 0,

        Err(e) => {
            client.partial_responses.remove(&stream_id);

            error!(
                "{} handle_writable stream send failed {:?}",
                conn.trace_id(),
                e
            );
            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

fn next(current: &mut mio::Token) -> mio::Token {
    let next = current.0;
    current.0 += 1;
    mio::Token(next)
}
