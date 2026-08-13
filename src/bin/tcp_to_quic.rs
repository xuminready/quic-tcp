use log::{debug, error, info, warn};
use quic_tcp::p2p::ReplayFilter;
use quic_tcp::*;
use ring::rand::{SecureRandom, SystemRandom};

struct P2pClientInfo {
    rendezvous_addr: std::net::SocketAddr,
    server_passcode: String,
    target_tcp_port: u16,
    target_name: String,
    std_socket_raw: std::net::UdpSocket,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut p2p_client_info: Option<P2pClientInfo> = None;
    let mut server_passcode = "secret123".to_string();

    let (mut udp_socket, mut peer_addr, tcp_local_addr) = if args[1] == "p2p" {
        if args.len() < 6 {
            print_usage(&args[0]);
            return Ok(());
        }
        let rendezvous_addr: std::net::SocketAddr = args[2]
            .parse()
            .map_err(|e| format!("Invalid Rendezvous server address: {}", e))?;
        let passcode = &args[3];
        server_passcode = passcode.to_string();
        let target_tcp_port: u16 = args[4]
            .parse()
            .map_err(|e| format!("Invalid Target TCP port: {}", e))?;
        let tcp_local_addr_str = &args[5];
        let tcp_local_addr: std::net::SocketAddr = tcp_local_addr_str
            .parse()
            .map_err(|e| format!("Invalid TCP local address: {}", e))?;

        println!(
            "P2P Mode: connecting to Rendezvous Server {} for target TCP Port {}",
            rendezvous_addr, target_tcp_port
        );
        println!("TCP Local Server: {}", tcp_local_addr);

        let (std_socket, peer_addr, target_name) =
            run_client_p2p_handshake(rendezvous_addr, passcode, target_tcp_port)?;
        info!("UDP hole punching succeeded on client side with peer {}", peer_addr);
        println!("UDP hole punching succeeded on client side with peer {}", peer_addr);
        let std_socket_raw = std_socket.try_clone()?;
        std_socket.set_nonblocking(true)?;
        let udp_socket = mio::net::UdpSocket::from_std(std_socket);
        p2p_client_info = Some(P2pClientInfo {
            rendezvous_addr,
            server_passcode: passcode.to_string(),
            target_tcp_port,
            target_name,
            std_socket_raw,
        });
        (udp_socket, peer_addr, tcp_local_addr)
    } else {
        if args.len() < 3 {
            print_usage(&args[0]);
            return Ok(());
        }
        let tcp_local_addr_str = &args[1];
        let udp_remote_addr_str = &args[2];
        if args.len() > 3 {
            server_passcode = args[3].clone();
        }

        let tcp_local_addr: std::net::SocketAddr = tcp_local_addr_str
            .parse()
            .map_err(|e| format!("Invalid TCP local address: {}", e))?;
        let udp_remote_addr: std::net::SocketAddr = udp_remote_addr_str
            .parse()
            .map_err(|e| format!("Invalid UDP remote address: {}", e))?;

        println!(
            "Direct Mode: connecting to Remote QUIC Server {}",
            udp_remote_addr
        );
        println!("TCP Local Server: {}", tcp_local_addr);

        let bind_addr = match udp_remote_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let udp_socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        (udp_socket, udp_remote_addr, tcp_local_addr)
    };

    let mut tcp_server = mio::net::TcpListener::bind(tcp_local_addr).unwrap();
    info!(
        "TCP listener bound to {}, waiting for local connections.",
        tcp_local_addr
    );
    poll.registry()
        .register(&mut tcp_server, TCP_TOKEN, mio::Interest::READABLE)
        .unwrap();

    poll.registry()
        .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
        .unwrap();

    let mut config = get_quic_config();

    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = udp_socket.local_addr().unwrap();
    let quic_connection = quiche::connect(
        Some(peer_addr.to_string().as_str()),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    info!("Initiating QUIC handshake with peer {}...", peer_addr);
    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        udp_socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let mut session = Session::new(quic_connection);
    let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);

    let mut current_stream_id: u64 = 4;
    let mut unique_token = mio::Token(UDP_TOKEN.0 + 1);
    let mut was_established = false;
    let mut last_recv_time = std::time::Instant::now();
    let mut last_probe_time = std::time::Instant::now();
    let mut auth_filter = ReplayFilter::new();

    loop {
        let timeout = session.conn.timeout().or(if !session.tcp_streams.is_empty()
            || !session.quic_partial_writes.is_empty()
            || !session.tcp_partial_writes.is_empty()
        {
            Some(std::time::Duration::from_millis(50))
        } else if p2p_client_info.is_some() {
            Some(std::time::Duration::from_secs(1))
        } else {
            None
        });
        poll.poll(&mut events, timeout).unwrap();

        // Send auth packet as soon as early data or established is ready
        session.send_auth_packet(&server_passcode);

        // Send periodic PING keepalive frames every 5s in P2P mode to keep NAT mapping alive
        if p2p_client_info.is_some()
            && last_probe_time.elapsed() >= std::time::Duration::from_secs(5)
        {
            if session.conn.is_established() || session.conn.is_in_early_data() {
                debug!("Sending periodic PING keepalive frame to maintain NAT mapping with peer {}", peer_addr);
                session.conn.send_ack_eliciting().ok();
                let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
            }
            last_probe_time = std::time::Instant::now();
        }

        let unreachability_reason = if session.conn.is_closed() {
            Some(format!("QUIC connection closed ({:?})", session.conn.stats()))
        } else if p2p_client_info.is_some()
            && session.conn.is_established()
            && last_recv_time.elapsed() > std::time::Duration::from_secs(15)
        {
            Some(format!(
                "No response to periodic PINGs received from server for {:.1}s",
                last_recv_time.elapsed().as_secs_f32()
            ))
        } else {
            None
        };

        if let Some(reason) = unreachability_reason {
            if let Some(ref info) = p2p_client_info {
                warn!(
                    "Hole punched UDP connection to server '{}' ({}) is no longer usable: {}. Reporting to Rendezvous Server and starting over UDP hole punching process...",
                    info.target_name, peer_addr, reason
                );
                println!(
                    "WARNING: Hole punched UDP socket to server '{}' ({}) is no longer usable ({}). Reporting to Rendezvous Server and starting over UDP hole punching process...",
                    info.target_name, peer_addr, reason
                );

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
                    &info.server_passcode,
                    info.target_tcp_port,
                ) {
                    Ok(addr) => {
                        info!(
                            "UDP hole punching restart succeeded! Restored endpoint: {}",
                            addr
                        );
                        println!(
                            "UDP hole punching restart succeeded! Restored endpoint: {}",
                            addr
                        );
                        addr
                    }
                    Err(e) => {
                        error!(
                            "[P2P Client ERROR] UDP hole punching reconnection failed: {}. Will retry on next probe interval.",
                            e
                        );
                        eprintln!(
                            "[P2P Client ERROR] UDP hole punching reconnection failed: {}. Will retry on next probe interval.",
                            e
                        );
                        info.std_socket_raw.set_nonblocking(true).ok();
                        poll.registry()
                            .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
                            .unwrap();
                        last_probe_time = std::time::Instant::now();
                        last_recv_time = std::time::Instant::now();
                        continue;
                    }
                };
                peer_addr = new_peer_addr;

                info.std_socket_raw.set_nonblocking(true).ok();
                poll.registry()
                    .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
                    .unwrap();

                let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                SystemRandom::new().fill(&mut scid[..]).unwrap();
                let scid = quiche::ConnectionId::from_ref(&scid);
                let local_addr = udp_socket.local_addr().unwrap();
                let quic_connection = quiche::connect(
                    Some(peer_addr.to_string().as_str()),
                    &scid,
                    local_addr,
                    peer_addr,
                    &mut config,
                )
                .unwrap();
                session = Session::new(quic_connection);
                let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
                was_established = false;
                current_stream_id = 4;
                last_recv_time = std::time::Instant::now();
                continue;
            } else {
                info!("connection closed, {:?}", session.conn.stats());
                return Ok(());
            }
        }

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

        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    debug!("UDP client read event");
                    let mut buf = [0; 65535];
                    'read: loop {
                        let (len, from) = match udp_socket.recv_from(&mut buf) {
                            Ok(v) => v,
                            Err(e) => {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    debug!("recv() would block");
                                    break 'read;
                                }
                                panic!("recv() failed: {e:?}");
                            }
                        };

                        if from == peer_addr {
                            last_recv_time = std::time::Instant::now();
                        }

                        debug!("UDP got {len} bytes");
                        let recv_info = quiche::RecvInfo {
                            to: udp_socket.local_addr().unwrap(),
                            from,
                        };

                        let read = match session.conn.recv(&mut buf[..len], recv_info) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("recv failed: {:?}", e);
                                continue 'read;
                            }
                        };
                        debug!("processed {read} bytes");
                    }

                    debug!("done reading");

                    if session.conn.is_closed() {
                        if p2p_client_info.is_none() {
                            info!("connection closed, {:?}", session.conn.stats());
                            return Ok(());
                        }
                    }

                    if session.conn.is_established() && !was_established {
                        info!("QUIC connection established");
                        was_established = true;
                    }

                    // Send auth packet if not sent yet
                    session.send_auth_packet(&server_passcode);

                    // Process all readable streams.
                    for stream_id in session.conn.readable() {
                        if stream_id == 0 {
                            match session.process_client_auth_reply(&server_passcode, &mut auth_filter) {
                                Ok(true) => {
                                    info!("[Auth OK] Direct/P2P connection authenticated successfully with remote server!");
                                    println!("[Auth OK] Direct/P2P connection authenticated successfully with remote server!");
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
                            debug!(
                                "Readable stream {} not found in tcp_streams (likely closed)",
                                stream_id
                            );
                            continue;
                        }
                        let done = match session.forward_quic_to_tcp(stream_id, &mut poll) {
                            Ok(v) => v,
                            Err(e) => {
                                if quic_tcp::session::is_disconnect_error(&e) {
                                    debug!("forward_quic_to_tcp stream {} disconnected: {}", stream_id, e);
                                } else {
                                    warn!("forward_quic_to_tcp failed: {:?}", e);
                                }
                                session.close_tcp_stream_by_id(stream_id, &mut poll);
                                true
                            }
                        };
                        if done {
                            info!("fin response received");
                        }
                    }

                    // Process all writable streams.
                    for stream_id in session.conn.writable() {
                        session.flush_pending_quic_write(stream_id);
                        if !session.tcp_streams.contains_key(&stream_id) {
                            continue;
                        }
                        if let Err(e) = session.forward_tcp_to_quic(stream_id, &mut poll) {
                            if quic_tcp::session::is_disconnect_error(&e) {
                                debug!("forward_tcp_to_quic stream {} disconnected: {}", stream_id, e);
                            } else {
                                warn!("forward_tcp_to_quic failed: {:?}", e);
                            }
                            session.close_tcp_stream_by_id(stream_id, &mut poll);
                        }
                    }

                    // Flush any pending QUIC writes that were buffered prior to connection establishment
                    let pending_quic_ids: Vec<u64> = session.quic_partial_writes.keys().copied().collect();
                    for stream_id in pending_quic_ids {
                        session.flush_pending_quic_write(stream_id);
                    }

                    // Retry any pending writes or delayed TCP reads once connection is established
                    let all_stream_ids: Vec<u64> = session.tcp_streams.keys().copied().collect();
                    for stream_id in all_stream_ids {
                        if session.tcp_streams.contains_key(&stream_id) && !session.quic_partial_writes.contains_key(&stream_id) {
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

                    let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
                }
                TCP_TOKEN => loop {
                    let (mut tcp_stream, address) = match tcp_server.accept() {
                        Ok((tcp_stream, address)) => (tcp_stream, address),
                        Err(e) if would_block(&e) => {
                            break;
                        }
                        Err(e) => {
                            eprint!("{}", e);
                            return Ok(());
                        }
                    };

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
                    debug!("🟢 new stream id: {} for {} 🟢", stream_id, address);
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
                        debug!("TCP client is writable");
                        match session.forward_quic_to_tcp(stream_id, &mut poll) {
                            Ok(closed) => {
                                if closed {
                                    info!("forward_quic_to_tcp returned closed=true for stream {}", stream_id);
                                    tcp_closed = true;
                                }
                            }
                            Err(e) => {
                                if quic_tcp::session::is_disconnect_error(&e) {
                                    debug!("forward_quic_to_tcp stream {} disconnected: {}", stream_id, e);
                                } else {
                                    warn!("forward_quic_to_tcp returned error for stream {}: {:?}", stream_id, e);
                                }
                                tcp_closed = true;
                            }
                        }
                    }

                    if event.is_readable() && !tcp_closed {
                        debug!("TCP client is readable");
                        match session.forward_tcp_to_quic(stream_id, &mut poll) {
                            Ok(closed) => {
                                if closed {
                                    info!("forward_tcp_to_quic returned closed=true for stream {}", stream_id);
                                    tcp_closed = true;
                                }
                            }
                            Err(e) => {
                                if quic_tcp::session::is_disconnect_error(&e) {
                                    debug!("forward_tcp_to_quic stream {} disconnected: {}", stream_id, e);
                                } else {
                                    warn!("forward_tcp_to_quic returned error for stream {}: {:?}", stream_id, e);
                                }
                                tcp_closed = true;
                            }
                        }
                    }

                    if tcp_closed {
                        info!("🟢 done, close tcp stream {}", stream_id);
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
        let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
    }
}

fn print_usage(bin_name: &str) {
    eprintln!("Usage (Direct Mode):");
    eprintln!("  {} <Local_TCP_IP:Port> <Remote_UDP_IP:Port> [Server_Passcode]", bin_name);
    eprintln!("Usage (P2P Mode):");
    eprintln!(
        "  {} p2p <Rendezvous_Server_IP:Port> <Server_Passcode> <Target_TCP_Port> <Local_TCP_IP:Port>",
        bin_name
    );
}