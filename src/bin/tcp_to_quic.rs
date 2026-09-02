use log::{debug, error, info, warn};
use quic_tcp::auth::ReplayFilter;
use quic_tcp::*;
use ring::rand::{SecureRandom, SystemRandom};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

struct P2pClientContext {
    rendezvous_addr: SocketAddr,
    tunnel_code: String,
    tunnel_id: String,
    std_socket_raw: std::net::UdpSocket,
}

enum ClientMode {
    Direct {
        local_tcp_addr: SocketAddr,
        remote_udp_addr: SocketAddr,
        tunnel_code: String,
    },
    P2p {
        rendezvous_addr: SocketAddr,
        local_tcp_addr: SocketAddr,
        tunnel_code: String,
    },
}

impl ClientMode {
    fn from_args(args: &[String]) -> Result<Self, String> {
        if args.len() < 2 {
            return Err("Not enough arguments".to_string());
        }

        if args[1] == "p2p" {
            // Support legacy: tcp-to-quic p2p <Rendezvous_IP:Port> <Passcode> <Target_TCP_Port> <Local_TCP_IP:Port>
            if args.len() >= 6 && args[3].parse::<SocketAddr>().is_err() && args[4].parse::<u16>().is_ok() {
                let rendezvous_addr: SocketAddr = args[2]
                    .parse()
                    .map(quic_tcp::normalize_socket_addr)
                    .map_err(|e| format!("Invalid Rendezvous server address: {}", e))?;
                let tunnel_code = args[3].clone();
                let local_tcp_addr: SocketAddr = args[5]
                    .parse()
                    .map(quic_tcp::normalize_socket_addr)
                    .map_err(|e| format!("Invalid TCP local address: {}", e))?;
                return Ok(ClientMode::P2p {
                    rendezvous_addr,
                    local_tcp_addr,
                    tunnel_code,
                });
            }

            if args.len() < 4 {
                return Err("Missing required P2P arguments. Expected: p2p <Rendezvous_IP:Port> <Local_TCP_IP:Port> [Code]".to_string());
            }

            let rendezvous_addr: SocketAddr = args[2]
                .parse()
                .map(quic_tcp::normalize_socket_addr)
                .map_err(|e| format!("Invalid Rendezvous server address: {}", e))?;
            let local_tcp_addr: SocketAddr = args[3]
                .parse()
                .map(quic_tcp::normalize_socket_addr)
                .map_err(|e| format!("Invalid TCP local address: {}", e))?;
            let tunnel_code = if args.len() > 4 {
                args[4].clone()
            } else {
                "secret123".to_string()
            };

            Ok(ClientMode::P2p {
                rendezvous_addr,
                local_tcp_addr,
                tunnel_code,
            })
        } else {
            let offset = if args[1] == "direct" { 1 } else { 0 };
            if args.len() < 3 + offset {
                return Err("Missing required Direct Mode arguments. Expected: [direct] <Local_TCP_IP:Port> <Remote_UDP_IP:Port> [Code]".to_string());
            }
            let local_tcp_addr: SocketAddr = args[1 + offset]
                .parse()
                .map(quic_tcp::normalize_socket_addr)
                .map_err(|e| format!("Invalid TCP local address: {}", e))?;
            let remote_udp_addr: SocketAddr = args[2 + offset]
                .parse()
                .map(quic_tcp::normalize_socket_addr)
                .map_err(|e| format!("Invalid Remote UDP address: {}", e))?;
            let tunnel_code = if args.len() > 3 + offset {
                args[3 + offset].clone()
            } else {
                "secret123".to_string()
            };

            Ok(ClientMode::Direct {
                local_tcp_addr,
                remote_udp_addr,
                tunnel_code,
            })
        }
    }
}

fn create_quic_connection(
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    config: &mut quiche::Config,
) -> Session {
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    let quic_conn = quiche::connect(
        Some(peer_addr.to_string().as_str()),
        &scid,
        local_addr,
        peer_addr,
        config,
    )
    .unwrap();

    info!("Initiating QUIC handshake with peer {}...", peer_addr);
    info!(
        "Connecting to {} from {} with scid {}",
        peer_addr,
        local_addr,
        hex_dump(&scid)
    );

    Session::new(quic_conn)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let mode = match ClientMode::from_args(&args) {
        Ok(m) => m,
        Err(_) => {
            print_usage(&args[0]);
            return Ok(());
        }
    };

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut p2p_ctx: Option<P2pClientContext> = None;
    let tunnel_code: String;

    let (mut udp_socket, mut peer_addr, tcp_local_addr) = match mode {
        ClientMode::P2p {
            rendezvous_addr,
            local_tcp_addr,
            tunnel_code: code,
        } => {
            tunnel_code = code.clone();
            println!(
                "P2P Mode: connecting to Rendezvous Server {} with secret code",
                rendezvous_addr
            );
            println!("TCP Local Listener: {}", local_tcp_addr);

            let (std_socket, peer_addr, tunnel_id) =
                run_client_p2p_handshake(rendezvous_addr, &tunnel_code)?;
            info!("UDP hole punching succeeded on client side with peer {}", peer_addr);
            println!("UDP hole punching succeeded on client side with peer {}", peer_addr);

            let std_socket_raw = std_socket.try_clone()?;
            optimize_udp_socket(&std_socket_raw);
            std_socket.set_nonblocking(true)?;
            let udp_socket = mio::net::UdpSocket::from_std(std_socket);

            p2p_ctx = Some(P2pClientContext {
                rendezvous_addr,
                tunnel_code: tunnel_code.clone(),
                tunnel_id,
                std_socket_raw,
            });

            (udp_socket, peer_addr, local_tcp_addr)
        }
        ClientMode::Direct {
            local_tcp_addr,
            remote_udp_addr,
            tunnel_code: code,
        } => {
            tunnel_code = code;
            println!("Direct Mode: connecting to Remote QUIC Server {}", remote_udp_addr);
            println!("TCP Local Listener: {}", local_tcp_addr);
            println!("Secret Code: {}", tunnel_code);

            let bind_addr = match remote_udp_addr {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };
            let std_sock = std::net::UdpSocket::bind(bind_addr.parse::<SocketAddr>().unwrap()).unwrap();
            optimize_udp_socket(&std_sock);
            std_sock.set_nonblocking(true)?;
            let udp_socket = mio::net::UdpSocket::from_std(std_sock);
            (udp_socket, remote_udp_addr, local_tcp_addr)
        }
    };

    let mut tcp_server = quic_tcp::bind_tcp_listener(tcp_local_addr).unwrap();
    info!("TCP listener bound to {}, waiting for QUIC tunnel authentication.", tcp_local_addr);
    let mut tcp_server_registered = false;

    poll.registry()
        .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
        .unwrap();

    let mut config = get_quic_config();
    let local_addr = udp_socket.local_addr().unwrap();
    let mut session = create_quic_connection(peer_addr, local_addr, &mut config);
    let _ = session.flush_quic_to_udp(&udp_socket);

    let mut current_stream_id: u64 = 4; // Streams start at 4 (stream 0 reserved for auth)
    let mut unique_token = mio::Token(UDP_TOKEN.0 + 1);
    let mut was_established = false;
    let mut last_recv_time = Instant::now();
    let mut last_probe_time = Instant::now();
    let mut auth_filter = ReplayFilter::new();

    loop {
        let has_active_streams = !session.tcp_streams.is_empty()
            || !session.quic_partial_writes.is_empty()
            || !session.tcp_partial_writes.is_empty();
        let mut timeout = session.conn.timeout();
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

        if session.is_authenticated && !tcp_server_registered {
            poll.registry()
                .register(&mut tcp_server, TCP_TOKEN, mio::Interest::READABLE)
                .unwrap();
            tcp_server_registered = true;
            info!("QUIC tunnel authenticated! TCP listener accepting connections on {}.", tcp_local_addr);
            println!("QUIC tunnel authenticated! TCP listener accepting connections on {}.", tcp_local_addr);
        }

        // Send stream 0 auth packet as soon as early data or established is ready
        session.send_auth_packet(&tunnel_code);

        // Send periodic PING keepalive frames every 5s in P2P mode to keep NAT mapping alive
        if p2p_ctx.is_some() && last_probe_time.elapsed() >= Duration::from_secs(5) {
            if session.conn.is_established() || session.conn.is_in_early_data() {
                debug!("Sending periodic PING keepalive to maintain NAT mapping with peer {}", peer_addr);
                session.conn.send_ack_eliciting().ok();
                let _ = session.flush_quic_to_udp(&udp_socket);
            }
            last_probe_time = Instant::now();
        }

        // Detect socket reachability and handle automatic reconnection in P2P mode
        let unreachability_reason = if session.conn.is_closed() {
            Some(format!("QUIC connection closed ({:?})", session.conn.stats()))
        } else if p2p_ctx.is_some()
            && session.conn.is_established()
            && last_recv_time.elapsed() > Duration::from_secs(15)
        {
            Some(format!(
                "No response to periodic PINGs received from server for {:.1}s",
                last_recv_time.elapsed().as_secs_f32()
            ))
        } else {
            None
        };

        if let Some(reason) = unreachability_reason {
            if let Some(ref info) = p2p_ctx {
                warn!(
                    "Hole punched UDP connection to server (Tunnel ID '{}', {}) is no longer usable: {}. Reporting to Rendezvous Server and restarting hole punching...",
                    info.tunnel_id, peer_addr, reason
                );
                println!(
                    "WARNING: Hole punched UDP socket to server (Tunnel ID '{}', {}) is no longer usable ({}). Reporting to Rendezvous Server and restarting hole punching...",
                    info.tunnel_id, peer_addr, reason
                );

                if tcp_server_registered {
                    poll.registry().deregister(&mut tcp_server).ok();
                    tcp_server_registered = false;
                }

                // Drain and deregister active TCP streams
                for (_, mut tcp_stream) in session.tcp_streams.drain() {
                    poll.registry().deregister(&mut tcp_stream).ok();
                }
                session.token_to_stream_id.clear();
                session.quic_partial_writes.clear();
                session.tcp_partial_writes.clear();
                session.opened_streams.clear();
                session.quic_read_done.clear();
                session.tcp_read_done.clear();

                poll.registry().deregister(&mut udp_socket).ok();
                info.std_socket_raw.set_nonblocking(false).ok();

                let new_peer_addr = match reconnect_client_p2p_handshake(
                    &info.std_socket_raw,
                    info.rendezvous_addr,
                    &info.tunnel_code,
                ) {
                    Ok(addr) => {
                        info!("UDP hole punching restart succeeded! Restored endpoint: {}", addr);
                        println!("UDP hole punching restart succeeded! Restored endpoint: {}", addr);
                        addr
                    }
                    Err(e) => {
                        error!("[P2P Client ERROR] UDP hole punching reconnection failed: {}. Retrying on next interval.", e);
                        eprintln!("[P2P Client ERROR] UDP hole punching reconnection failed: {}. Retrying on next interval.", e);
                        info.std_socket_raw.set_nonblocking(true).ok();
                        poll.registry()
                            .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
                            .unwrap();
                        last_probe_time = Instant::now();
                        last_recv_time = Instant::now();
                        continue;
                    }
                };
                peer_addr = new_peer_addr;

                info.std_socket_raw.set_nonblocking(true).ok();
                poll.registry()
                    .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
                    .unwrap();

                session = create_quic_connection(peer_addr, local_addr, &mut config);
                let _ = session.flush_quic_to_udp(&udp_socket);
                was_established = false;
                current_stream_id = 4;
                last_recv_time = Instant::now();
                continue;
            } else {
                info!("Direct connection closed: {:?}", session.conn.stats());
                return Ok(());
            }
        }

        // Flush pending queued writes
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
                    if quic_tcp::session::is_disconnect_error(&e) {
                        debug!("forward_tcp_to_quic stream {} disconnected: {}", stream_id, e);
                    } else {
                        warn!("Failed to forward TCP to QUIC for stream {}: {:?}", stream_id, e);
                    }
                    session.close_tcp_stream_by_id(stream_id, &mut poll);
                }
            }
        }
        let _ = session.flush_quic_to_udp(&udp_socket);

        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    let mut buf = [0; 65535];
                    'read: loop {
                        let (len, from) = match udp_socket.recv_from(&mut buf) {
                            Ok(v) => v,
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    break 'read;
                                }
                                panic!("recv() failed: {e:?}");
                            }
                        };
                        let from = quic_tcp::normalize_socket_addr(from);

                        let pkt_buf = &mut buf[..len];

                        if let Some(ref info) = p2p_ctx {
                            if from == info.rendezvous_addr {
                                debug!("Ignoring packet from Rendezvous Server in client data loop");
                                continue 'read;
                            }
                        }

                        if pkt_buf.starts_with(b"PEER_") {
                            debug!("Ignoring trailing hole punch probe from {}", from);
                            continue 'read;
                        }

                        if from == peer_addr {
                            last_recv_time = Instant::now();
                        }

                        let recv_info = quiche::RecvInfo {
                            to: local_addr,
                            from,
                        };

                        if let Err(e) = session.conn.recv(pkt_buf, recv_info) {
                            debug!("recv failed: {:?}", e);
                            continue 'read;
                        }
                    }

                    if session.conn.is_closed() && p2p_ctx.is_none() {
                        info!("Connection closed: {:?}", session.conn.stats());
                        return Ok(());
                    }

                    if session.conn.is_established() && !was_established {
                        info!("QUIC connection established");
                        was_established = true;
                    }

                    // Send auth packet if not sent yet
                    session.send_auth_packet(&tunnel_code);

                    // Process all readable streams (ensuring Stream 0 is processed first)
                    let mut readable_streams: Vec<u64> = session.conn.readable().collect();
                    if let Some(pos) = readable_streams.iter().position(|&s| s == 0) {
                        readable_streams.remove(pos);
                        readable_streams.insert(0, 0);
                    }

                    for stream_id in readable_streams {
                        if stream_id == 0 {
                            match session.process_client_auth_reply(&tunnel_code, &mut auth_filter) {
                                Ok(true) => {
                                    info!("[Auth OK] Direct/P2P connection authenticated successfully with remote server!");
                                    println!("[Auth OK] Direct/P2P connection authenticated successfully with remote server!");
                                    if !tcp_server_registered {
                                        poll.registry()
                                            .register(&mut tcp_server, TCP_TOKEN, mio::Interest::READABLE)
                                            .unwrap();
                                        tcp_server_registered = true;
                                        info!("QUIC tunnel authenticated! TCP listener accepting connections on {}.", tcp_local_addr);
                                        println!("QUIC tunnel authenticated! TCP listener accepting connections on {}.", tcp_local_addr);
                                    }
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    error!("[Auth ERROR] Authentication failed with remote server: {}. Closing connection.", e);
                                    eprintln!("[Auth ERROR] Authentication failed with remote server: {}. Closing connection.", e);
                                }
                            }
                            continue;
                        }

                        session.opened_streams.insert(stream_id);
                        if !session.tcp_streams.contains_key(&stream_id) {
                            continue;
                        }
                        if let Err(e) = session.forward_quic_to_tcp(stream_id, &mut poll) {
                            if quic_tcp::session::is_disconnect_error(&e) {
                                debug!("forward_quic_to_tcp stream {} disconnected: {}", stream_id, e);
                            } else {
                                warn!("forward_quic_to_tcp failed: {:?}", e);
                            }
                            session.close_tcp_stream_by_id(stream_id, &mut poll);
                        }
                    }

                    // Process all writable streams
                    for stream_id in session.conn.writable() {
                        session.flush_pending_quic_write(stream_id);
                        if session.tcp_streams.contains_key(&stream_id) {
                            if let Err(e) = session.forward_tcp_to_quic(stream_id, &mut poll) {
                                if quic_tcp::session::is_disconnect_error(&e) {
                                    debug!("forward_tcp_to_quic stream {} disconnected: {}", stream_id, e);
                                } else {
                                    warn!("forward_tcp_to_quic failed: {:?}", e);
                                }
                                session.close_tcp_stream_by_id(stream_id, &mut poll);
                            }
                        }
                    }

                    // Check for finished or reset streams
                    let active_streams: Vec<u64> = session.tcp_streams.keys().copied().collect();
                    for stream_id in active_streams {
                        let is_finished = session.conn.stream_finished(stream_id);
                        let is_dead = session.opened_streams.contains(&stream_id)
                            && session.conn.stream_capacity(stream_id).is_err();
                        if is_finished || is_dead {
                            debug!("QUIC stream {} finished or reset, closing local TCP stream", stream_id);
                            session.close_tcp_stream_by_id(stream_id, &mut poll);
                        }
                    }

                    let _ = session.flush_quic_to_udp(&udp_socket);
                    debug!("tcp-to-quic UDP_TOKEN end stats: {:?}", session.conn.stats());
                }
                TCP_TOKEN => loop {
                    let (mut tcp_stream, address) = match tcp_server.accept() {
                        Ok((tcp_stream, address)) => (tcp_stream, address),
                        Err(e) if would_block(&e) => break,
                        Err(e) => {
                            eprintln!("TCP Accept error: {}", e);
                            return Ok(());
                        }
                    };

                    if !session.is_authenticated {
                        debug!("Rejecting TCP connection from {} because QUIC tunnel is not authenticated", address);
                        drop(tcp_stream);
                        continue;
                    }

                    optimize_tcp_stream(&tcp_stream);
                    info!("Accepted TCP connection from: {}", address);
                    let token = next_token(&mut unique_token);
                    poll.registry()
                        .register(
                            &mut tcp_stream,
                            token,
                            mio::Interest::READABLE.add(mio::Interest::WRITABLE),
                        )
                        .unwrap();

                    let stream_id = next_stream_id(&mut current_stream_id);
                    debug!("🟢 New stream id: {} for {} 🟢", stream_id, address);
                    session.token_to_stream_id.insert(token, stream_id);
                    session.tcp_streams.insert(stream_id, tcp_stream);
                },
                token => {
                    let Some(stream_id) = session.token_to_stream_id.get(&token).copied() else {
                        continue;
                    };
                    if !session.tcp_streams.contains_key(&stream_id) {
                        continue;
                    }

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
                        let _ = session.flush_quic_to_udp(&udp_socket);
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
                        let _ = session.flush_quic_to_udp(&udp_socket);
                    }

                    if tcp_closed {
                        info!("🟢 Closing TCP stream {}", stream_id);
                        session.close_tcp_stream_by_token(token, &mut poll);
                    }
                }
            }
        }

        session.conn.on_timeout();
        let pending_ids: Vec<u64> = session.quic_partial_writes.keys().copied().collect();
        for stream_id in pending_ids {
            session.flush_pending_quic_write(stream_id);
        }
        let _ = session.flush_quic_to_udp(&udp_socket);
    }
}

fn print_usage(bin_name: &str) {
    eprintln!("Usage (Direct Mode):");
    eprintln!("  {} [direct] <Local_TCP_IP:Port> <Remote_UDP_IP:Port> [Secret_Code]", bin_name);
    eprintln!("  Example: {} 127.0.0.1:7070 127.0.0.1:4433 my_secret", bin_name);
    eprintln!();
    eprintln!("Usage (P2P Mode):");
    eprintln!(
        "  {} p2p <Rendezvous_Server_IP:Port> <Local_TCP_IP:Port> [Secret_Code]",
        bin_name
    );
    eprintln!("  Example: {} p2p 1.2.3.4:5050 127.0.0.1:7070 my_secret", bin_name);
}
