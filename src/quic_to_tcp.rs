use crate::auth::{ReplayFilter, normalize_secret};
use crate::protocol::{PeerRelease, PeerReleaseAck, PunchSignal};
use crate::session::{Session, is_disconnect_error};
use crate::{
    MAX_DATAGRAM_SIZE, UDP_TOKEN, clear_shutdown, get_quic_config, interrupted,
    is_shutdown_requested, mint_token, next_token, normalize_socket_addr, optimize_tcp_stream,
    optimize_udp_socket, run_server_p2p_handshake, send_server_keepalive, send_server_status,
    server_handle_reconnect_punch, validate_token,
};
use log::{debug, error, info, warn};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const DEFAULT_CERT_PEM: &str = include_str!("../cert.crt");
const DEFAULT_KEY_PEM: &str = include_str!("../cert.key");

type ClientMap = HashMap<quiche::ConnectionId<'static>, Session>;

struct P2pServerContext {
    rendezvous_addr: SocketAddr,
    tunnel_id: String,
    tcp_port: u16,
    tunnel_code: String,
    std_socket_raw: std::net::UdpSocket,
    last_keepalive: Instant,
    status: String,
}

#[derive(Debug, Clone)]
pub enum ServerMode {
    Direct {
        local_udp_addr: SocketAddr,
        remote_tcp_addr: SocketAddr,
        tunnel_code: String,
    },
    P2p {
        rendezvous_addr: SocketAddr,
        remote_tcp_addr: SocketAddr,
        tunnel_code: String,
    },
}

impl ServerMode {
    pub fn from_args(args: &[String]) -> Result<Self, String> {
        if args.len() < 2 {
            return Err("Not enough arguments".to_string());
        }

        if args[1] == "p2p" {
            // Support simplified syntax: quic-to-tcp p2p <Rendezvous_IP:Port> <Remote_TCP_IP:Port> [Code]
            // Also supports legacy syntax: quic-to-tcp p2p <Rendezvous_IP:Port> <Name> <Rdv_Pass> <Srv_Pass> <Remote_TCP_IP:Port>
            if args.len() >= 6 && args[3].parse::<SocketAddr>().is_err() {
                let rendezvous_addr: SocketAddr = args[2]
                    .parse()
                    .map(normalize_socket_addr)
                    .map_err(|e| format!("Invalid Rendezvous server address: {}", e))?;
                let remote_tcp_addr_str = if args.len() >= 7 { &args[6] } else { &args[5] };
                let remote_tcp_addr: SocketAddr = remote_tcp_addr_str
                    .parse()
                    .map(normalize_socket_addr)
                    .map_err(|e| format!("Invalid TCP remote address: {}", e))?;
                let tunnel_code = if args.len() >= 7 {
                    normalize_secret(&args[5])
                } else {
                    normalize_secret(&args[4])
                };
                return Ok(ServerMode::P2p {
                    rendezvous_addr,
                    remote_tcp_addr,
                    tunnel_code,
                });
            }

            if args.len() < 4 {
                return Err("Missing required P2P arguments. Expected: p2p <Rendezvous_IP:Port> <Remote_TCP_IP:Port> [Code]".to_string());
            }
            if args.len() > 5 {
                if let Some(pos) = args[4..].iter().rposition(|a| a == "p2p" || a == "direct") {
                    let tail_start = 4 + pos;
                    let mut clean_args = vec![args[0].clone()];
                    clean_args.extend_from_slice(&args[tail_start..]);
                    warn!(
                        "Detected duplicated command on CLI; using trailing arguments: {:?}",
                        &clean_args[1..]
                    );
                    return Self::from_args(&clean_args);
                }
                return Err(format!(
                    "Unexpected extra arguments after Secret_Code: {:?}. (Check if a command was pasted twice or if '!' triggered shell history expansion)",
                    &args[5..]
                ));
            }

            let rendezvous_addr: SocketAddr = args[2]
                .parse()
                .map(normalize_socket_addr)
                .map_err(|e| format!("Invalid Rendezvous server address: {}", e))?;
            let remote_tcp_addr: SocketAddr = args[3]
                .parse()
                .map(normalize_socket_addr)
                .map_err(|e| format!("Invalid TCP remote address: {}", e))?;
            let tunnel_code = if args.len() > 4 {
                normalize_secret(&args[4])
            } else {
                "secret123".to_string()
            };

            Ok(ServerMode::P2p {
                rendezvous_addr,
                remote_tcp_addr,
                tunnel_code,
            })
        } else {
            let offset = if args[1] == "direct" { 1 } else { 0 };
            if args.len() < 3 + offset {
                return Err("Missing required Direct Mode arguments. Expected: [direct] <Local_UDP_IP:Port> <Remote_TCP_IP:Port> [Code]".to_string());
            }
            if args.len() > 4 + offset {
                return Err(format!(
                    "Unexpected extra arguments after Secret_Code: {:?}. (Check if a command was pasted twice or if '!' triggered shell history expansion)",
                    &args[(4 + offset)..]
                ));
            }
            let local_udp_addr: SocketAddr = args[1 + offset]
                .parse()
                .map(normalize_socket_addr)
                .map_err(|e| format!("Invalid UDP local address: {}", e))?;
            let remote_tcp_addr: SocketAddr =
                args[2 + offset]
                    .parse()
                    .map(normalize_socket_addr)
                    .map_err(|e| format!("Invalid TCP remote address: {}", e))?;
            let tunnel_code = if args.len() > 3 + offset {
                normalize_secret(&args[3 + offset])
            } else {
                "secret123".to_string()
            };

            Ok(ServerMode::Direct {
                local_udp_addr,
                remote_tcp_addr,
                tunnel_code,
            })
        }
    }
}

fn ensure_tls_cert_files() -> Result<(String, String), String> {
    let cert_env = std::env::var("QUIC_CERT_PATH").unwrap_or_else(|_| "cert.crt".to_string());
    let key_env = std::env::var("QUIC_KEY_PATH").unwrap_or_else(|_| "cert.key".to_string());

    if std::path::Path::new(&cert_env).exists() && std::path::Path::new(&key_env).exists() {
        return Ok((cert_env, key_env));
    }

    let base_dir = std::env::var("QUIC_CERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let _ = std::fs::create_dir_all(&base_dir);
    let cert_path = base_dir.join("quic_tcp_cert.crt");
    let key_path = base_dir.join("quic_tcp_cert.key");

    if !cert_path.exists() {
        std::fs::write(&cert_path, DEFAULT_CERT_PEM).map_err(|e| {
            format!(
                "Failed to write embedded TLS cert to {:?}: {}",
                cert_path, e
            )
        })?;
    }
    if !key_path.exists() {
        std::fs::write(&key_path, DEFAULT_KEY_PEM)
            .map_err(|e| format!("Failed to write embedded TLS key to {:?}: {}", key_path, e))?;
    }

    Ok((
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    ))
}

fn connect_and_forward_stream(
    session: &mut Session,
    stream_id: u64,
    tcp_remote_addr: SocketAddr,
    poll: &mut mio::Poll,
    unique_token: &mut mio::Token,
    token_scid_map: &mut HashMap<mio::Token, quiche::ConnectionId<'static>>,
) {
    session.opened_streams.insert(stream_id);
    if let std::collections::hash_map::Entry::Vacant(entry) = session.tcp_streams.entry(stream_id) {
        let token = next_token(unique_token);
        let mut tcp_stream = match mio::net::TcpStream::connect(tcp_remote_addr) {
            Ok(stream) => stream,
            Err(e) => {
                error!(
                    "Failed to connect to remote TCP server {}: {:?}",
                    tcp_remote_addr, e
                );
                session
                    .conn
                    .stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
                    .ok();
                session
                    .conn
                    .stream_shutdown(stream_id, quiche::Shutdown::Write, 0)
                    .ok();
                return;
            }
        };
        optimize_tcp_stream(&tcp_stream);
        if let Err(e) = poll.registry().register(
            &mut tcp_stream,
            token,
            mio::Interest::READABLE.add(mio::Interest::WRITABLE),
        ) {
            error!("Failed to register TCP stream with poll: {:?}", e);
            return;
        }
        entry.insert(tcp_stream);
        session.token_to_stream_id.insert(token, stream_id);

        let scid = quiche::ConnectionId::from_vec(session.conn.source_id().as_ref().to_vec());
        token_scid_map.insert(token, scid);
    }

    if let Err(e) = session.forward_quic_to_tcp(stream_id, poll) {
        if !is_disconnect_error(&e) {
            warn!(
                "forward_quic_to_tcp error for stream {}: {:?}",
                stream_id, e
            );
        }
        session.close_tcp_stream_by_id(stream_id, poll);
        token_scid_map.retain(|tok, _| session.token_to_stream_id.contains_key(tok));
    }
}

/// Runs the `quic-to-tcp` server proxy loop until shutdown is requested or an unrecoverable error occurs.
pub fn run_quic_to_tcp(mode: ServerMode) -> Result<(), Box<dyn std::error::Error>> {
    clear_shutdown();

    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(1024);

    let mut p2p_ctx: Option<P2pServerContext> = None;
    let tunnel_code: String;

    let (mut udp_socket, tcp_remote_addr) = match mode {
        ServerMode::P2p {
            rendezvous_addr,
            remote_tcp_addr,
            tunnel_code: code,
        } => {
            tunnel_code = code.clone();
            let tcp_port = remote_tcp_addr.port();

            info!(
                "[quic-to-tcp] Starting P2P Mode -> Rendezvous: {}, Forwarding To TCP: {}, Secret: {:?}",
                rendezvous_addr, remote_tcp_addr, tunnel_code
            );
            let (std_socket, tunnel_id) =
                run_server_p2p_handshake(rendezvous_addr, &tunnel_code, tcp_port)?;
            info!("UDP hole punching succeeded on server side!");

            info!(
                "[+] Tunnel ID: {} | Forwarding To: {} | Rendezvous: {}",
                tunnel_id, remote_tcp_addr, rendezvous_addr
            );
            println!("======================================================================");
            println!("[+] Tunnel ID:       {}", tunnel_id);
            println!("[+] Forwarding To:   {}", remote_tcp_addr);
            println!("[+] Rendezvous:      {}", rendezvous_addr);
            println!("[+] Secret Code:     {}", tunnel_code);
            println!(
                "[+] Connect with:    tcp-to-quic p2p {} 127.0.0.1:{} {}",
                rendezvous_addr, tcp_port, tunnel_code
            );
            println!("======================================================================");

            let std_socket_raw = std_socket.try_clone()?;
            optimize_udp_socket(&std_socket_raw);
            std_socket.set_nonblocking(true)?;
            let udp_socket = mio::net::UdpSocket::from_std(std_socket);

            p2p_ctx = Some(P2pServerContext {
                rendezvous_addr,
                tunnel_id,
                tcp_port,
                tunnel_code: tunnel_code.clone(),
                std_socket_raw,
                last_keepalive: Instant::now(),
                status: "BUSY".to_string(),
            });

            (udp_socket, remote_tcp_addr)
        }
        ServerMode::Direct {
            local_udp_addr,
            remote_tcp_addr,
            tunnel_code: code,
        } => {
            tunnel_code = code;
            info!(
                "[quic-to-tcp] Direct Mode: listening on UDP {}, forwarding to TCP {}",
                local_udp_addr, remote_tcp_addr
            );
            println!("Direct Mode: listening on UDP {}", local_udp_addr);
            println!("TCP Remote Server: {}", remote_tcp_addr);
            println!("Secret Code: {}", tunnel_code);

            let std_sock = std::net::UdpSocket::bind(local_udp_addr)?;
            optimize_udp_socket(&std_sock);
            std_sock.set_nonblocking(true)?;
            let udp_socket = mio::net::UdpSocket::from_std(std_sock);
            (udp_socket, remote_tcp_addr)
        }
    };

    poll.registry()
        .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)?;

    let mut config = get_quic_config();
    let (cert_path, key_path) = ensure_tls_cert_files()?;
    config
        .load_cert_chain_from_pem_file(&cert_path)
        .map_err(|e| {
            format!(
                "Failed to load TLS certificate from '{}': {:?}",
                cert_path, e
            )
        })?;
    config.load_priv_key_from_pem_file(&key_path).map_err(|e| {
        format!(
            "Failed to load TLS private key from '{}': {:?}",
            key_path, e
        )
    })?;
    config.enable_early_data();

    let rng = SystemRandom::new();
    let mut conn_id_seed = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut conn_id_seed[..])
        .map_err(|_| "Failed to generate random connection ID seed")?;

    let mut sessions = ClientMap::new();
    let mut established_conns = std::collections::HashSet::new();
    let local_addr = udp_socket.local_addr()?;
    let mut token_scid_map: HashMap<mio::Token, quiche::ConnectionId> = HashMap::new();
    let mut buf = [0; 65535];
    let mut unique_token = mio::Token(UDP_TOKEN.0 + 1);
    let mut last_ping_time = Instant::now();
    let mut peer_auth_filter = ReplayFilter::new();

    'main_loop: loop {
        if is_shutdown_requested() {
            break 'main_loop;
        }

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
        } else {
            timeout = Some(std::cmp::min(
                timeout.unwrap_or(Duration::from_millis(100)),
                Duration::from_millis(100),
            ));
        }
        if let Err(e) = poll.poll(&mut events, timeout) {
            if interrupted(&e) {
                if is_shutdown_requested() {
                    break 'main_loop;
                }
                continue 'main_loop;
            }
            return Err(format!("poll failed: {:?}", e).into());
        }

        if is_shutdown_requested() {
            break 'main_loop;
        }

        // Send periodic keepalive to Rendezvous Server in P2P mode
        if let Some(ref mut info) = p2p_ctx {
            if info.last_keepalive.elapsed() >= Duration::from_secs(10) {
                let _ = send_server_keepalive(
                    &info.std_socket_raw,
                    info.rendezvous_addr,
                    &info.tunnel_id,
                    info.tcp_port,
                    &info.status,
                    &info.tunnel_code,
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
                    let _ = session.flush_quic_to_udp(&udp_socket);
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
                        if !is_disconnect_error(&e) {
                            warn!(
                                "Failed to forward TCP to QUIC for stream {}: {:?}",
                                stream_id, e
                            );
                        }
                        session.close_tcp_stream_by_id(stream_id, &mut poll);
                    }
                }
            }
            let _ = session.flush_quic_to_udp(&udp_socket);
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
                                if interrupted(&e) {
                                    continue 'read;
                                }
                                return Err(format!("recv() failed: {:?}", e).into());
                            }
                        };
                        let from = normalize_socket_addr(from);

                        let pkt_buf = &mut buf[..len];

                        // Intercept control PUNCH packets from Rendezvous Server for reconnection
                        if let Some(ref mut info) = p2p_ctx {
                            if from == info.rendezvous_addr {
                                let text = std::str::from_utf8(pkt_buf).unwrap_or("").trim();
                                if let Some(signal) = PunchSignal::parse(text) {
                                    if signal.verify(&info.tunnel_code)
                                        && peer_auth_filter.check_and_add(signal.seq())
                                    {
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

                                            let reconnect_res = server_handle_reconnect_punch(
                                                &info.std_socket_raw,
                                                client_addr,
                                                info.rendezvous_addr,
                                                &info.tunnel_id,
                                                info.tcp_port,
                                                &info.tunnel_code,
                                            );

                                            info.std_socket_raw.set_nonblocking(true).ok();
                                            poll.registry().register(
                                                &mut udp_socket,
                                                UDP_TOKEN,
                                                mio::Interest::READABLE,
                                            )?;
                                            info.last_keepalive = Instant::now();
                                            if reconnect_res.is_ok() {
                                                info.status = "BUSY".to_string();
                                            } else {
                                                warn!(
                                                    "[P2P Server Reconnect] Hole punching failed with client {}. Re-registered as IDLE at Rendezvous Server.",
                                                    client_addr
                                                );
                                                info.status = "IDLE".to_string();
                                            }
                                        }
                                    }
                                } else {
                                    debug!(
                                        "Received control packet from Rendezvous Server: {}",
                                        text
                                    );
                                }
                                continue 'read;
                            }
                        }

                        // Handle PEER_RELEASE or ignore trailing UDP hole punching probes from peer
                        if pkt_buf.starts_with(b"PEER_") {
                            let text = std::str::from_utf8(pkt_buf).unwrap_or("").trim();
                            if let Some(release) = PeerRelease::parse(text) {
                                if release.verify(&tunnel_code) {
                                    if peer_auth_filter.check_and_add(release.seq) {
                                        info!(
                                            "[Server] Received authenticated PEER_RELEASE from client {}. Releasing session and transitioning to IDLE.",
                                            from
                                        );
                                        for (_, mut s) in sessions.drain() {
                                            for (_, mut stream) in s.tcp_streams.drain() {
                                                poll.registry().deregister(&mut stream).ok();
                                            }
                                            s.conn.close(true, 0x00, b"client_release").ok();
                                        }
                                        established_conns.clear();
                                        token_scid_map.clear();

                                        if let Some(ref mut info) = p2p_ctx {
                                            if info.status != "IDLE" {
                                                info.status = "IDLE".to_string();
                                                let _ = send_server_status(
                                                    &info.std_socket_raw,
                                                    info.rendezvous_addr,
                                                    &info.tunnel_id,
                                                    "IDLE",
                                                    &info.tunnel_code,
                                                );
                                                info!(
                                                    "[P2P Server] Server status transitioned back to IDLE after client release."
                                                );
                                            }
                                        }
                                    }
                                    let ack = PeerReleaseAck::new_signed(&tunnel_code);
                                    let _ = udp_socket.send_to(ack.as_bytes(), from);
                                } else {
                                    warn!("Ignored unauthenticated PEER_RELEASE from {}", from);
                                }
                            } else {
                                debug!("Ignoring trailing hole punch probe from {}", from);
                            }
                            continue 'read;
                        }

                        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN)
                        {
                            Ok(v) => v,
                            Err(e) => {
                                debug!("Failed to parse QUIC header: {:?}", e);
                                continue 'read;
                            }
                        };

                        let conn_id = quiche::ConnectionId::from_vec(hdr.dcid.as_ref().to_vec());

                        let session = if !sessions.contains_key(&conn_id) {
                            if hdr.ty != quiche::Type::Initial {
                                debug!(
                                    "Ignoring non-Initial packet for unknown connection from {}",
                                    from
                                );
                                continue 'read;
                            }

                            if !quiche::version_is_supported(hdr.version) {
                                warn!("Negotiating version with {}", from);
                                let mut out = [0; MAX_DATAGRAM_SIZE];
                                let len =
                                    quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)?;
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
                                )?;
                                let _ = udp_socket.send_to(&out[..len], from);
                                continue 'read;
                            }

                            let odcid = validate_token(&from, token);
                            if odcid.is_none() || scid.len() != hdr.dcid.len() {
                                error!("Invalid address validation token or DCID");
                                continue 'read;
                            }

                            let scid = hdr.dcid.clone();
                            info!(
                                "Received QUIC Initial packet from client {}. Initializing session...",
                                from
                            );

                            let conn = quiche::accept(
                                &scid,
                                odcid.as_ref(),
                                local_addr,
                                from,
                                &mut config,
                            )?;

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
                                            &info.tunnel_id,
                                            "BUSY",
                                            &info.tunnel_code,
                                        );
                                        info!("[P2P Server] Server status transitioned to BUSY.");
                                    }
                                }
                            }
                        }
                    }

                    // Process readable and writable streams for all active sessions after draining UDP
                    for session in sessions.values_mut() {
                        if session.conn.is_in_early_data() || session.conn.is_established() {
                            let mut readable_streams: Vec<u64> = session.conn.readable().collect();
                            // Process Stream 0 authentication first if present
                            if let Some(pos) = readable_streams.iter().position(|&s| s == 0) {
                                readable_streams.remove(pos);
                                readable_streams.insert(0, 0);
                            }

                            for stream_id in readable_streams {
                                if stream_id == 0 {
                                    match session
                                        .process_server_auth(&tunnel_code, &mut peer_auth_filter)
                                    {
                                        Ok(true) => {
                                            info!(
                                                "[Auth OK] Direct/P2P client authenticated successfully with valid secret code!"
                                            );
                                            println!(
                                                "[Auth OK] Direct/P2P client authenticated successfully with valid secret code!"
                                            );
                                        }
                                        Ok(false) => {}
                                        Err(e) => {
                                            error!(
                                                "[Auth ERROR] Client authentication failed: {}. Closing connection.",
                                                e
                                            );
                                            eprintln!(
                                                "[Auth ERROR] Client authentication failed: {}. Closing connection.",
                                                e
                                            );
                                        }
                                    }
                                    continue;
                                }

                                if !session.is_authenticated {
                                    debug!(
                                        "Stream {} received data before Stream 0 authentication completed. Queuing.",
                                        stream_id
                                    );
                                    session.unauthenticated_readable_streams.insert(stream_id);
                                    continue;
                                }

                                connect_and_forward_stream(
                                    session,
                                    stream_id,
                                    tcp_remote_addr,
                                    &mut poll,
                                    &mut unique_token,
                                    &mut token_scid_map,
                                );
                            }

                            // Process any previously queued streams once authenticated
                            if session.is_authenticated
                                && !session.unauthenticated_readable_streams.is_empty()
                            {
                                let pending: Vec<u64> =
                                    session.unauthenticated_readable_streams.drain().collect();
                                for stream_id in pending {
                                    connect_and_forward_stream(
                                        session,
                                        stream_id,
                                        tcp_remote_addr,
                                        &mut poll,
                                        &mut unique_token,
                                        &mut token_scid_map,
                                    );
                                }
                            }

                            for stream_id in session.conn.writable() {
                                session.flush_pending_quic_write(stream_id);
                                if session.tcp_streams.contains_key(&stream_id) {
                                    if let Err(e) =
                                        session.forward_tcp_to_quic(stream_id, &mut poll)
                                    {
                                        if !is_disconnect_error(&e) {
                                            warn!(
                                                "forward_tcp_to_quic error for stream {}: {:?}",
                                                stream_id, e
                                            );
                                        }
                                        session.close_tcp_stream_by_id(stream_id, &mut poll);
                                    }
                                }
                            }

                            // Check for finished or reset streams
                            let active_streams: Vec<u64> =
                                session.tcp_streams.keys().copied().collect();
                            for stream_id in active_streams {
                                let is_finished = session.conn.stream_finished(stream_id);
                                let is_dead = session.opened_streams.contains(&stream_id)
                                    && session.conn.stream_capacity(stream_id).is_err();
                                if is_finished || is_dead {
                                    debug!(
                                        "QUIC stream {} finished or reset, closing remote TCP stream",
                                        stream_id
                                    );
                                    session.close_tcp_stream_by_id(stream_id, &mut poll);
                                    token_scid_map.retain(|tok, _| {
                                        session.token_to_stream_id.contains_key(tok)
                                    });
                                }
                            }
                        }
                    }

                    for session in sessions.values_mut() {
                        let _ = session.flush_quic_to_udp(&udp_socket);
                    }
                }
                token => {
                    let Some(scid) = token_scid_map.get(&token) else {
                        continue;
                    };
                    let Some(session) = sessions.get_mut(scid) else {
                        continue;
                    };
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
                                if !is_disconnect_error(&e) {
                                    warn!(
                                        "forward_quic_to_tcp error for stream {}: {:?}",
                                        stream_id, e
                                    );
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
                                if !is_disconnect_error(&e) {
                                    warn!(
                                        "forward_tcp_to_quic error for stream {}: {:?}",
                                        stream_id, e
                                    );
                                }
                                tcp_closed = true;
                            }
                        }
                        let _ = session.flush_quic_to_udp(&udp_socket);
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
            let _ = session.flush_quic_to_udp(&udp_socket);
        }

        // Garbage collect closed connections
        let closed_connections: Vec<_> = sessions
            .iter()
            .filter(|(_, s)| s.conn.is_closed())
            .map(|(k, _)| k.clone())
            .collect();
        let had_closed = !closed_connections.is_empty();

        for scid in closed_connections {
            established_conns.remove(&scid);
            if let Some(mut session) = sessions.remove(&scid) {
                info!(
                    "Connection {} collected: {:?}",
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

        if let Some(ref mut info) = p2p_ctx {
            if had_closed && sessions.is_empty() && info.status == "BUSY" {
                info.status = "IDLE".to_string();
                let _ = send_server_status(
                    &info.std_socket_raw,
                    info.rendezvous_addr,
                    &info.tunnel_id,
                    "IDLE",
                    &info.tunnel_code,
                );
                info!(
                    "[P2P Server] All client sessions disconnected. Transitioned server status back to IDLE."
                );
            }
        }
    }

    for (_, mut s) in sessions.drain() {
        for (_, mut stream) in s.tcp_streams.drain() {
            poll.registry().deregister(&mut stream).ok();
        }
        s.conn.close(true, 0x00, b"server_shutdown").ok();
        let _ = s.flush_quic_to_udp(&udp_socket);
    }

    if let Some(ref info) = p2p_ctx {
        let _ = send_server_status(
            &info.std_socket_raw,
            info.rendezvous_addr,
            &info.tunnel_id,
            "IDLE",
            &info.tunnel_code,
        );
    }

    info!("[quic-to-tcp] Server stopped cleanly.");
    Ok(())
}
