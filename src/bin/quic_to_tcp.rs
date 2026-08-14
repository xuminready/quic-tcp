use log::{debug, error, info, warn};
use quic_tcp::auth::ReplayFilter;
use quic_tcp::protocol::PunchSignal;
use quic_tcp::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

type ClientMap = HashMap<quiche::ConnectionId<'static>, Session>;

struct P2pServerContext {
    rendezvous_addr: SocketAddr,
    name: String,
    tcp_port: u16,
    server_passcode: String,
    rendezvous_passcode: String,
    std_socket_raw: std::net::UdpSocket,
    last_keepalive: Instant,
    status: String,
}

enum ServerMode {
    Direct {
        local_udp_addr: SocketAddr,
        remote_tcp_addr: SocketAddr,
        server_passcode: String,
    },
    P2p {
        rendezvous_addr: SocketAddr,
        name: String,
        rendezvous_passcode: String,
        server_passcode: String,
        remote_tcp_addr: SocketAddr,
    },
}

impl ServerMode {
    fn from_args(args: &[String]) -> Result<Self, String> {
        if args.len() < 2 {
            return Err("Not enough arguments".to_string());
        }

        if args[1] == "p2p" {
            if args.len() < 6 {
                return Err("Missing required P2P arguments".to_string());
            }
            let rendezvous_addr: SocketAddr = args[2]
                .parse()
                .map_err(|e| format!("Invalid Rendezvous server address: {}", e))?;
            let name = args[3].clone();
            let (rendezvous_passcode, server_passcode, remote_tcp_addr_str) = if args.len() >= 7 {
                (args[4].clone(), args[5].clone(), &args[6])
            } else {
                (args[4].clone(), args[4].clone(), &args[5])
            };
            let remote_tcp_addr: SocketAddr = remote_tcp_addr_str
                .parse()
                .map_err(|e| format!("Invalid TCP remote address: {}", e))?;

            Ok(ServerMode::P2p {
                rendezvous_addr,
                name,
                rendezvous_passcode,
                server_passcode,
                remote_tcp_addr,
            })
        } else {
            if args.len() < 3 {
                return Err("Missing required Direct Mode arguments".to_string());
            }
            let local_udp_addr: SocketAddr = args[1]
                .parse()
                .map_err(|e| format!("Invalid UDP local address: {}", e))?;
            let remote_tcp_addr: SocketAddr = args[2]
                .parse()
                .map_err(|e| format!("Invalid TCP remote address: {}", e))?;
            let server_passcode = if args.len() > 3 {
                args[3].clone()
            } else {
                "secret123".to_string()
            };

            Ok(ServerMode::Direct {
                local_udp_addr,
                remote_tcp_addr,
                server_passcode,
            })
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let mode = match ServerMode::from_args(&args) {
        Ok(m) => m,
        Err(_) => {
            print_usage(&args[0]);
            return Ok(());
        }
    };

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut p2p_ctx: Option<P2pServerContext> = None;
    let server_passcode: String;

    let (mut udp_socket, tcp_remote_addr) = match mode {
        ServerMode::P2p {
            rendezvous_addr,
            name,
            rendezvous_passcode,
            server_passcode: srv_pass,
            remote_tcp_addr,
        } => {
            server_passcode = srv_pass.clone();
            let tcp_port = remote_tcp_addr.port();

            println!(
                "P2P Mode: registering at Rendezvous Server {} as '{}' (TCP Port: {})",
                rendezvous_addr, name, tcp_port
            );
            println!("TCP Remote Server: {}", remote_tcp_addr);

            let std_socket = run_server_p2p_handshake(
                rendezvous_addr,
                &name,
                &rendezvous_passcode,
                &server_passcode,
                tcp_port,
            )?;
            info!("UDP hole punching succeeded on server side!");
            println!("UDP hole punching succeeded on server side!");

            let std_socket_raw = std_socket.try_clone()?;
            std_socket.set_nonblocking(true)?;
            let udp_socket = mio::net::UdpSocket::from_std(std_socket);

            p2p_ctx = Some(P2pServerContext {
                rendezvous_addr,
                name,
                tcp_port,
                server_passcode: server_passcode.clone(),
                rendezvous_passcode,
                std_socket_raw,
                last_keepalive: Instant::now(),
                status: "IDLE".to_string(),
            });

            (udp_socket, remote_tcp_addr)
        }
        ServerMode::Direct {
            local_udp_addr,
            remote_tcp_addr,
            server_passcode: srv_pass,
        } => {
            server_passcode = srv_pass;
            println!("Direct Mode: listening on UDP {}", local_udp_addr);
            println!("TCP Remote Server: {}", remote_tcp_addr);

            let udp_socket = mio::net::UdpSocket::bind(local_udp_addr).unwrap();
            (udp_socket, remote_tcp_addr)
        }
    };

    poll.registry()
        .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
        .unwrap();

    let mut config = get_quic_config();
    config.load_cert_chain_from_pem_file("cert.crt").unwrap();
    config.load_priv_key_from_pem_file("cert.key").unwrap();
    config.enable_early_data();

    let rng = SystemRandom::new();
    let mut conn_id_seed = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut conn_id_seed[..]).unwrap();

    let mut sessions = ClientMap::new();
    let mut established_conns = std::collections::HashSet::new();
    let local_addr = udp_socket.local_addr().unwrap();
    let mut token_scid_map: HashMap<mio::Token, quiche::ConnectionId> = HashMap::new();
    let mut buf = [0; 65535];
    let mut unique_token = mio::Token(UDP_TOKEN.0 + 1);
    let mut last_ping_time = Instant::now();
    let mut peer_auth_filter = ReplayFilter::new();

    loop {
        let min_conn_timeout = sessions.values().filter_map(|s| s.conn.timeout()).min();
        let has_active_streams = sessions.values().any(|s| {
            !s.tcp_streams.is_empty()
                || !s.quic_partial_writes.is_empty()
                || !s.tcp_partial_writes.is_empty()
        });
        let mut timeout = min_conn_timeout;
        if has_active_streams {
            timeout = Some(std::cmp::min(
                timeout.unwrap_or(Duration::from_millis(50)),
                Duration::from_millis(50),
            ));
        } else if p2p_ctx.is_some() {
            timeout = Some(std::cmp::min(
                timeout.unwrap_or(Duration::from_secs(1)),
                Duration::from_secs(1),
            ));
        }
        poll.poll(&mut events, timeout).unwrap();

        // Send periodic keepalive to Rendezvous Server in P2P mode
        if let Some(ref mut info) = p2p_ctx {
            if info.last_keepalive.elapsed() >= Duration::from_secs(10) {
                let _ = send_server_keepalive(
                    &info.std_socket_raw,
                    info.rendezvous_addr,
                    &info.name,
                    info.tcp_port,
                    &info.status,
                    &info.server_passcode,
                    &info.rendezvous_passcode,
                );
                info.last_keepalive = Instant::now();
            }
        }

        // Send periodic PING keepalive frames over QUIC in P2P mode
        if p2p_ctx.is_some() && last_ping_time.elapsed() >= Duration::from_secs(5) {
            for session in sessions.values_mut() {
                if session.conn.is_established() || session.conn.is_in_early_data() {
                    debug!("Sending periodic PING keepalive to maintain NAT mapping");
                    session.conn.send_ack_eliciting().ok();
                    let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
                }
            }
            last_ping_time = Instant::now();
        }

        for session in sessions.values_mut() {
            let pending_ids: Vec<u64> = session.quic_partial_writes.keys().copied().collect();
            for stream_id in pending_ids {
                session.flush_pending_quic_write(stream_id);
            }

            let pending_tcp_ids: Vec<u64> = session.tcp_partial_writes.keys().copied().collect();
            for stream_id in pending_tcp_ids {
                let _ = session.flush_pending_tcp_write(stream_id);
                if !session.tcp_partial_writes.contains_key(&stream_id) {
                    let _ = session.forward_quic_to_tcp(stream_id, &mut poll);
                }
            }

            let active_streams: Vec<u64> = session.tcp_streams.keys().copied().collect();
            for stream_id in active_streams {
                if session.tcp_streams.contains_key(&stream_id)
                    && !session.quic_partial_writes.contains_key(&stream_id)
                    && !session.tcp_read_done.contains(&stream_id)
                {
                    if let Err(e) = session.forward_tcp_to_quic(stream_id, &mut poll) {
                        if !quic_tcp::session::is_disconnect_error(&e) {
                            warn!("Failed to forward TCP to QUIC for stream {}: {:?}", stream_id, e);
                        }
                        session.close_tcp_stream_by_id(stream_id, &mut poll);
                    }
                }
            }
        }

        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    'read: loop {
                        let (len, from) = match udp_socket.recv_from(&mut buf) {
                            Ok(v) => v,
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    break 'read;
                                }
                                panic!("recv() failed: {:?}", e);
                            }
                        };

                        let pkt_buf = &mut buf[..len];

                        // Intercept control PUNCH packets from Rendezvous Server for reconnection
                        if let Some(ref mut info) = p2p_ctx {
                            if from == info.rendezvous_addr {
                                let text = std::str::from_utf8(pkt_buf).unwrap_or("").trim();
                                if let Some(signal) = PunchSignal::parse(text) {
                                    if signal.verify(&info.server_passcode) {
                                        if let PunchSignal::Passive { client_addr, .. } = signal {
                                            warn!(
                                                "[P2P Server Reconnect] Received authenticated PUNCH request from client {}. Resetting sessions and starting hole punching...",
                                                client_addr
                                            );
                                            for (_, mut s) in sessions.drain() {
                                                for (_, mut stream) in s.tcp_streams.drain() {
                                                    poll.registry().deregister(&mut stream).ok();
                                                }
                                                s.conn.close(true, 0x00, b"reconnect").ok();
                                            }
                                            established_conns.clear();
                                            token_scid_map.clear();

                                            poll.registry().deregister(&mut udp_socket).ok();
                                            info.std_socket_raw.set_nonblocking(false).ok();

                                            let _ = server_handle_reconnect_punch(
                                                &info.std_socket_raw,
                                                client_addr,
                                                info.rendezvous_addr,
                                                &info.name,
                                                info.tcp_port,
                                                &info.server_passcode,
                                                &info.rendezvous_passcode,
                                            );

                                            info.std_socket_raw.set_nonblocking(true).ok();
                                            poll.registry()
                                                .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
                                                .unwrap();
                                            info.last_keepalive = Instant::now();
                                            info.status = "BUSY".to_string();
                                            continue 'read;
                                        }
                                    }
                                }
                            }
                        }

                        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Failed to parse QUIC header: {:?}", e);
                                continue 'read;
                            }
                        };

                        let conn_id = quiche::ConnectionId::from_vec(hdr.dcid.as_ref().to_vec());

                        let session = if !sessions.contains_key(&conn_id) {
                            if hdr.ty != quiche::Type::Initial {
                                error!("Packet is not Initial");
                                continue 'read;
                            }

                            if !quiche::version_is_supported(hdr.version) {
                                warn!("Negotiating version with {}", from);
                                let mut out = [0; MAX_DATAGRAM_SIZE];
                                let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();
                                let _ = udp_socket.send_to(&out[..len], from);
                                continue 'read;
                            }

                            let scid = quiche::ConnectionId::from_vec(conn_id_seed.to_vec());

                            let token = hdr.token.as_ref().unwrap();
                            if token.is_empty() {
                                let new_token = mint_token(&hdr, &from);
                                let mut out = [0; MAX_DATAGRAM_SIZE];
                                let len = quiche::retry(
                                    &hdr.scid,
                                    &hdr.dcid,
                                    &scid,
                                    &new_token,
                                    hdr.version,
                                    &mut out,
                                )
                                .unwrap();
                                let _ = udp_socket.send_to(&out[..len], from);
                                continue 'read;
                            }

                            let odcid = validate_token(&from, token);
                            if odcid.is_none() || scid.len() != hdr.dcid.len() {
                                error!("Invalid address validation token or DCID");
                                continue 'read;
                            }

                            let scid = hdr.dcid.clone();
                            info!("Received QUIC Initial packet from client {}. Initializing session...", from);

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
                            sessions.get_mut(&conn_id).unwrap()
                        };

                        let recv_info = quiche::RecvInfo {
                            to: local_addr,
                            from,
                        };

                        if let Err(e) = session.conn.recv(pkt_buf, recv_info) {
                            error!("session recv failed: {:?}", e);
                            continue 'read;
                        }

                        if session.conn.is_established() {
                            let dcid = quiche::ConnectionId::from_vec(hdr.dcid.as_ref().to_vec());
                            if !established_conns.contains(&dcid) {
                                established_conns.insert(dcid);
                                if let Some(ref mut info) = p2p_ctx {
                                    if info.status != "BUSY" {
                                        info.status = "BUSY".to_string();
                                        let _ = send_server_status(
                                            &info.std_socket_raw,
                                            info.rendezvous_addr,
                                            &info.name,
                                            "BUSY",
                                            &info.rendezvous_passcode,
                                        );
                                        info!("[P2P Server] Server status transitioned to BUSY.");
                                    }
                                }
                            }
                        }

                        // Process readable streams (Stream 0 auth or TCP proxy streams)
                        if session.conn.is_in_early_data() || session.conn.is_established() {
                            for stream_id in session.conn.readable() {
                                if stream_id == 0 {
                                    match session.process_server_auth(&server_passcode, &mut peer_auth_filter) {
                                        Ok(true) => {
                                            info!("[Auth OK] Direct/P2P client authenticated successfully with valid server passcode!");
                                            println!("[Auth OK] Direct/P2P client authenticated successfully with valid server passcode!");
                                        }
                                        Ok(false) => {}
                                        Err(e) => {
                                            error!("[Auth ERROR] Client authentication failed: {}. Closing connection.", e);
                                            eprintln!("[Auth ERROR] Client authentication failed: {}. Closing connection.", e);
                                        }
                                    }
                                    continue;
                                }

                                if !session.is_authenticated {
                                    warn!("Stream {} received data before Stream 0 authentication completed. Dropping data.", stream_id);
                                    continue;
                                }

                                session.opened_streams.insert(stream_id);
                                if let std::collections::hash_map::Entry::Vacant(entry) =
                                    session.tcp_streams.entry(stream_id)
                                {
                                    let token = next_token(&mut unique_token);
                                    let mut tcp_stream = match mio::net::TcpStream::connect(tcp_remote_addr) {
                                        Ok(stream) => stream,
                                        Err(e) => {
                                            error!("Failed to connect to remote TCP server {}: {:?}", tcp_remote_addr, e);
                                            session.conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0).ok();
                                            continue;
                                        }
                                    };
                                    poll.registry()
                                        .register(
                                            &mut tcp_stream,
                                            token,
                                            mio::Interest::READABLE.add(mio::Interest::WRITABLE),
                                        )
                                        .unwrap();
                                    entry.insert(tcp_stream);
                                    session.token_to_stream_id.insert(token, stream_id);

                                    let scid = quiche::ConnectionId::from_vec(session.conn.source_id().as_ref().to_vec());
                                    token_scid_map.insert(token, scid);
                                }

                                if let Err(e) = session.forward_quic_to_tcp(stream_id, &mut poll) {
                                    if !quic_tcp::session::is_disconnect_error(&e) {
                                        warn!("forward_quic_to_tcp error for stream {}: {:?}", stream_id, e);
                                    }
                                    session.close_tcp_stream_by_id(stream_id, &mut poll);
                                    token_scid_map.retain(|tok, _| session.token_to_stream_id.contains_key(tok));
                                }
                            }
                        }
                    }

                    for session in sessions.values_mut() {
                        let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
                    }
                }
                token => {
                    let Some(scid) = token_scid_map.get(&token) else { continue; };
                    let Some(session) = sessions.get_mut(scid) else { continue; };
                    let Some(stream_id) = session.token_to_stream_id.get(&token).copied() else { continue; };

                    if !session.tcp_streams.contains_key(&stream_id) { continue; }

                    let mut tcp_closed = false;

                    if event.is_writable() {
                        match session.forward_quic_to_tcp(stream_id, &mut poll) {
                            Ok(closed) => tcp_closed = closed,
                            Err(e) => {
                                if !quic_tcp::session::is_disconnect_error(&e) {
                                    warn!("forward_quic_to_tcp error for stream {}: {:?}", stream_id, e);
                                }
                                tcp_closed = true;
                            }
                        }
                    }

                    if event.is_readable() && !tcp_closed {
                        match session.forward_tcp_to_quic(stream_id, &mut poll) {
                            Ok(closed) => tcp_closed = closed,
                            Err(e) => {
                                if !quic_tcp::session::is_disconnect_error(&e) {
                                    warn!("forward_tcp_to_quic error for stream {}: {:?}", stream_id, e);
                                }
                                tcp_closed = true;
                            }
                        }
                    }

                    if tcp_closed {
                        debug!("Closing TCP stream {}", stream_id);
                        session.close_tcp_stream_by_token(token, &mut poll);
                        token_scid_map.remove(&token);
                    }
                }
            }
        }

        for session in sessions.values_mut() {
            session.conn.on_timeout();
            let pending_ids: Vec<u64> = session.quic_partial_writes.keys().copied().collect();
            for stream_id in pending_ids {
                session.flush_pending_quic_write(stream_id);
            }
            let pending_tcp_ids: Vec<u64> = session.tcp_partial_writes.keys().copied().collect();
            for stream_id in pending_tcp_ids {
                let _ = session.flush_pending_tcp_write(stream_id);
                if !session.tcp_partial_writes.contains_key(&stream_id) {
                    let _ = session.forward_quic_to_tcp(stream_id, &mut poll);
                }
            }
            let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
        }

        // Garbage collect closed connections
        let closed_connections: Vec<_> = sessions
            .iter()
            .filter(|(_, s)| s.conn.is_closed())
            .map(|(k, _)| k.clone())
            .collect();

        for scid in closed_connections {
            established_conns.remove(&scid);
            if let Some(mut session) = sessions.remove(&scid) {
                info!("Connection {} collected: {:?}", session.conn.trace_id(), session.conn.stats());
                for (token, _) in session.token_to_stream_id.iter() {
                    token_scid_map.remove(token);
                }
                for (_, mut tcp_stream) in session.tcp_streams.drain() {
                    poll.registry().deregister(&mut tcp_stream).ok();
                }
            }
        }

        if let Some(ref mut info) = p2p_ctx {
            if sessions.is_empty() && info.status == "BUSY" {
                info.status = "IDLE".to_string();
                let _ = send_server_status(
                    &info.std_socket_raw,
                    info.rendezvous_addr,
                    &info.name,
                    "IDLE",
                    &info.rendezvous_passcode,
                );
                info!("[P2P Server] All client sessions disconnected. Transitioned server status back to IDLE.");
            }
        }
    }
}

fn print_usage(bin_name: &str) {
    eprintln!("Usage (Direct Mode):");
    eprintln!("  {} <Local_UDP_IP:Port> <Remote_TCP_IP:Port> [Server_Passcode]", bin_name);
    eprintln!("Usage (P2P Mode):");
    eprintln!(
        "  {} p2p <Rendezvous_Server_IP:Port> <Name> <Rendezvous_Passcode> <Server_Passcode> <Remote_TCP_IP:Port>",
        bin_name
    );
}
