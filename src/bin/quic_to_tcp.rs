use log::{debug, error, info, warn};
use quic_tcp::*;
use ring::rand::SystemRandom;
use std::collections::HashMap; // Import our library

type ClientMap = HashMap<quiche::ConnectionId<'static>, Session>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let (mut udp_socket, tcp_remote_addr) = if args[1] == "p2p" {
        if args.len() < 7 {
            print_usage(&args[0]);
            return Ok(());
        }
        let rendezvous_addr: std::net::SocketAddr = args[2]
            .parse()
            .map_err(|e| format!("Invalid Rendezvous server address: {}", e))?;
        let name = &args[3];
        let cap = &args[4];
        let loc = &args[5];
        let tcp_remote_addr_str = &args[6];
        let tcp_remote_addr: std::net::SocketAddr = tcp_remote_addr_str
            .parse()
            .map_err(|e| format!("Invalid TCP remote address: {}", e))?;

        println!(
            "P2P Mode: registering at Rendezvous Server {} as '{}'",
            rendezvous_addr, name
        );
        println!("TCP Remote Server: {}", tcp_remote_addr);

        let std_socket = run_server_p2p_handshake(rendezvous_addr, name, cap, loc)?;
        std_socket.set_nonblocking(true)?;
        let udp_socket = mio::net::UdpSocket::from_std(std_socket);
        (udp_socket, tcp_remote_addr)
    } else {
        if args.len() < 3 {
            print_usage(&args[0]);
            return Ok(());
        }
        let udp_local_addr_str = &args[1];
        let tcp_remote_addr_str = &args[2];

        let udp_local_addr: std::net::SocketAddr = udp_local_addr_str
            .parse()
            .map_err(|e| format!("Invalid UDP local address: {}", e))?;
        let tcp_remote_addr: std::net::SocketAddr = tcp_remote_addr_str
            .parse()
            .map_err(|e| format!("Invalid TCP remote address: {}", e))?;

        println!("Direct Mode: listening on UDP {}", udp_local_addr);
        println!("TCP Remote Server: {}", tcp_remote_addr);

        let udp_socket = mio::net::UdpSocket::bind(udp_local_addr).unwrap();
        (udp_socket, tcp_remote_addr)
    };

    poll.registry()
        .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
        .unwrap();

    let mut config = get_quic_config();
    config.load_cert_chain_from_pem_file("cert.crt").unwrap();
    config.load_priv_key_from_pem_file("cert.key").unwrap();
    config.enable_early_data();

    let rng = SystemRandom::new();
    let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut sessions = ClientMap::new();
    let mut established_conns = std::collections::HashSet::new();
    let local_addr = udp_socket.local_addr().unwrap();
    let mut token_scid_map: HashMap<mio::Token, quiche::ConnectionId> = HashMap::new();
    let mut buf = [0; 65535];
    let mut unique_token = mio::Token(UDP_TOKEN.0 + 1);

    loop {
        let timeout = sessions.values().filter_map(|s| s.conn.timeout()).min();
        poll.poll(&mut events, timeout).unwrap();

        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    debug!("UDP server readable event");
                    'read: loop {
                        let (len, from) = match udp_socket.recv_from(&mut buf) {
                            Ok(v) => v,
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    debug!("recv() would block");
                                    break 'read;
                                }
                                panic!("recv() failed: {:?}", e);
                            }
                        };

                        debug!("got {} bytes", len);
                        let pkt_buf = &mut buf[..len];

                        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN)
                        {
                            Ok(v) => v,
                            Err(e) => {
                                debug!(
                                    "Parsing packet header failed: {:?} (len: {}, from: {}, data: {:?})",
                                    e,
                                    len,
                                    from,
                                    &pkt_buf[..std::cmp::min(len, 32)]
                                );
                                continue 'read;
                            }
                        };

                        let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                        let conn_id = conn_id.to_vec().into();

                        let session = if !sessions.contains_key(&hdr.dcid)
                            && !sessions.contains_key(&conn_id)
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
                                debug!(
                                    "-> Sent Version Negotiation ({} bytes) to {}",
                                    out.len(),
                                    from
                                );
                                if let Err(e) = udp_socket.send_to(out, from) {
                                    if e.kind() == std::io::ErrorKind::WouldBlock {
                                        break;
                                    }
                                    panic!("send() failed: {:?}", e);
                                }
                                continue 'read;
                            }

                            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                            scid.copy_from_slice(&conn_id);
                            let scid = quiche::ConnectionId::from_ref(&scid);

                            let token = hdr.token.as_ref().unwrap();
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
                                debug!("-> Sent Stateless Retry ({} bytes) to {}", out.len(), from);
                                if let Err(e) = udp_socket.send_to(out, from) {
                                    if e.kind() == std::io::ErrorKind::WouldBlock {
                                        break;
                                    }
                                    panic!("send() failed: {:?}", e);
                                }
                                continue 'read;
                            }

                            let odcid = validate_token(&from, token);
                            if odcid.is_none() {
                                error!("Invalid address validation token");
                                continue 'read;
                            }

                            if scid.len() != hdr.dcid.len() {
                                error!("Invalid destination connection ID");
                                continue 'read;
                            }

                            let scid = hdr.dcid.clone();
                            info!(
                                "Received QUIC Initial packet from client {}. Initializing session...",
                                from
                            );
                            info!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                            let conn = quiche::accept(
                                &scid,
                                odcid.as_ref(),
                                local_addr,
                                from,
                                &mut config,
                            )
                            .unwrap();
                            let session = Session::new(conn);
                            sessions.insert(scid.clone(), session);
                            sessions.get_mut(&scid).unwrap()
                        } else {
                            match sessions.get_mut(&hdr.dcid) {
                                Some(v) => v,
                                None => sessions.get_mut(&conn_id).unwrap(),
                            }
                        };

                        let recv_info = quiche::RecvInfo {
                            to: udp_socket.local_addr().unwrap(),
                            from,
                        };

                        let read = match session.conn.recv(pkt_buf, recv_info) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("{} recv failed: {:?}", session.conn.trace_id(), e);
                                continue 'read;
                            }
                        };
                        debug!("{} processed {} bytes", session.conn.trace_id(), read);

                        if session.conn.is_established() && !established_conns.contains(&hdr.dcid) {
                            info!("QUIC connection established with client {}!", from);
                            established_conns
                                .insert(quiche::ConnectionId::from_vec(hdr.dcid.as_ref().to_vec()));
                        }

                        if session.conn.is_in_early_data() || session.conn.is_established() {
                            // Handle writable streams.
                            for stream_id in session.conn.writable() {
                                if session.tcp_streams.contains_key(&stream_id) {
                                    session.forward_tcp_to_quic(stream_id, &mut poll).ok();
                                }
                            }
                            // Process all readable streams.
                            for stream_id in session.conn.readable() {
                                session.opened_streams.insert(stream_id);
                                if let std::collections::hash_map::Entry::Vacant(entry) =
                                    session.tcp_streams.entry(stream_id)
                                {
                                    let token = next_token(&mut unique_token);
                                    info!("Create a new TCP connection for stream id {stream_id}");
                                    let mut tcp_stream =
                                        mio::net::TcpStream::connect(tcp_remote_addr).unwrap();
                                    poll.registry()
                                        .register(
                                            &mut tcp_stream,
                                            token,
                                            mio::Interest::READABLE.add(mio::Interest::WRITABLE),
                                        )
                                        .unwrap();
                                    entry.insert(tcp_stream);
                                    session.token_to_stream_id.insert(token, stream_id);

                                    let scid = quiche::ConnectionId::from_vec(
                                        session.conn.source_id().as_ref().to_vec(),
                                    );
                                    token_scid_map.insert(token, scid);
                                }

                                session.forward_quic_to_tcp(stream_id, &mut poll).ok();
                            }
                        } else {
                            debug!("Not early data neither established");
                        }
                    }
                }
                token => {
                    let Some(scid) = token_scid_map.get(&token) else {
                        debug!("Token {:?} not found in token_scid_map", token);
                        continue;
                    };
                    let Some(session) = sessions.get_mut(scid) else {
                        debug!("Session not found for scid {:?}", scid);
                        continue;
                    };

                    let mut tcp_closed = false;

                    if event.is_writable() {
                        debug!("TCP client is writable");
                        if let Some(stream_id) = session.token_to_stream_id.get(&token).copied() {
                            tcp_closed |= session
                                .forward_quic_to_tcp(stream_id, &mut poll)
                                .unwrap_or(true);
                        }
                    }

                    if event.is_readable() && !tcp_closed {
                        debug!("TCP client is readable");
                        if let Some(stream_id) = session.token_to_stream_id.get(&token).copied() {
                            tcp_closed |= session
                                .forward_tcp_to_quic(stream_id, &mut poll)
                                .unwrap_or(true);
                        }
                    }

                    if tcp_closed {
                        debug!("done, close tcp stream");
                        session.close_tcp_stream_by_token(token, &mut poll);
                        token_scid_map.remove(&token);
                    }
                }
            }
        }

        for session in sessions.values_mut() {
            session.conn.on_timeout();
            let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
        }

        // Garbage collect closed connections.
        let closed_connections: Vec<_> = sessions
            .iter()
            .filter(|(_, s)| s.conn.is_closed())
            .map(|(k, _)| k.clone())
            .collect();

        for scid in closed_connections {
            established_conns.remove(&scid);
            if let Some(mut session) = sessions.remove(&scid) {
                info!(
                    "{} connection collected {:?}",
                    session.conn.trace_id(),
                    session.conn.stats()
                );
                for (token, _) in session.token_to_stream_id.iter() {
                    token_scid_map.remove(token);
                }
                for (_, mut tcp_stream) in session.tcp_streams.drain() {
                    poll.registry().deregister(&mut tcp_stream).ok();
                }
            }
        }
    }
}

fn print_usage(bin_name: &str) {
    eprintln!("Usage (Direct Mode):");
    eprintln!("  {} <Local_UDP_IP:Port> <Remote_TCP_IP:Port>", bin_name);
    eprintln!("Usage (P2P Mode):");
    eprintln!(
        "  {} p2p <Rendezvous_Server_IP:Port> <Name> <Capacity> <Location> <Remote_TCP_IP:Port>",
        bin_name
    );
}
