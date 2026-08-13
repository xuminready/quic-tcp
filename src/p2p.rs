use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::utils::hex_dump;

pub fn compute_auth(passcode: &str, payload: &str) -> String {
    let s_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, passcode.as_bytes());
    let tag = ring::hmac::sign(&s_key, payload.as_bytes());
    hex_dump(tag.as_ref())
}

pub fn verify_auth(passcode: &str, payload: &str, signature: &str) -> bool {
    let expected = compute_auth(passcode, payload);
    expected == signature
}

static SEQ_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn next_seq() -> u64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let cnt = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed) % 1024;
    (now_ms << 10) | cnt
}

#[derive(Debug, Clone)]
pub struct ReplayFilter {
    pub seen_seqs: HashSet<u64>,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self {
            seen_seqs: HashSet::new(),
        }
    }

    pub fn check_and_add(&mut self, seq: u64) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let pkt_time_ms = seq >> 10;

        // Verify window within 120 seconds of clock to prevent ancient replay packets
        if pkt_time_ms > now_ms + 120_000 || now_ms.saturating_sub(pkt_time_ms) > 120_000 {
            return false;
        }

        if self.seen_seqs.contains(&seq) {
            return false; // Replay attack detected
        }

        self.seen_seqs.insert(seq);
        if self.seen_seqs.len() > 10_000 {
            self.seen_seqs.retain(|&s| {
                let time_ms = s >> 10;
                now_ms.saturating_sub(time_ms) <= 120_000
            });
        }
        true
    }
}

/// Performs UDP hole punching between two peers with multi-round retries, progress logging, and replay-protected HMAC authentication.
/// Returns the final learned SocketAddr of the peer or an Error if all retries fail.
pub fn perform_hole_punching(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
    passcode: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    socket.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut peer_addr = peer_addr;
    let mut buf = [0; 1024];
    let mut replay_filter = ReplayFilter::new();

    let max_rounds = 3;
    let attempts_per_round = 20;

    info!(
        "[P2P Hole Punch] Initiating UDP hole punching to peer endpoint {} (Max rounds: {}, Probes/round: {})...",
        peer_addr, max_rounds, attempts_per_round
    );
    println!(
        "[P2P Hole Punch] Initiating UDP hole punching to peer endpoint {} (Max rounds: {}, Probes/round: {})...",
        peer_addr, max_rounds, attempts_per_round
    );

    for round in 1..=max_rounds {
        let mut punched = false;
        let mut ack_ack_sends = 0;
        let mut current_step = 1; // 1: PEER_PUNCH, 2: PEER_PUNCH_ACK, 3: PEER_PUNCH_ACK_ACK

        info!(
            "[P2P Hole Punch] [Progress: Round {}/{}] Sending outbound punch probes to {}...",
            round, max_rounds, peer_addr
        );
        println!(
            "[P2P Hole Punch] [Progress: Round {}/{}] Sending outbound punch probes to {}...",
            round, max_rounds, peer_addr
        );

        for attempt in 1..=attempts_per_round {
            let seq = next_seq();
            let (cmd, payload) = match current_step {
                1 => ("PEER_PUNCH", format!("PEER_PUNCH:{}", seq)),
                2 => ("PEER_PUNCH_ACK", format!("PEER_PUNCH_ACK:{}", seq)),
                _ => ("PEER_PUNCH_ACK_ACK", format!("PEER_PUNCH_ACK_ACK:{}", seq)),
            };
            let hmac = compute_auth(passcode, &payload);
            let msg = format!("{} {} {}", cmd, seq, hmac);
            socket.send_to(msg.as_bytes(), peer_addr)?;

            debug!(
                "[P2P Hole Punch] [Round {}/{} Probe #{}] Sent '{}' to {}",
                round, max_rounds, attempt, cmd, peer_addr
            );

            if punched {
                ack_ack_sends += 1;
                if ack_ack_sends >= 4 {
                    break;
                }
            }

            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    let text = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if src.ip() == peer_addr.ip() && parts.len() >= 3 {
                        let cmd = parts[0];
                        let pkt_seq = parts[1].parse::<u64>().unwrap_or(0);
                        let pkt_hmac = parts[2];
                        let expected_payload = format!("{}:{}", cmd, pkt_seq);

                        if !verify_auth(passcode, &expected_payload, pkt_hmac) {
                            debug!("[P2P Hole Punch] Dropping packet with invalid HMAC from {}", src);
                            continue;
                        }
                        if !replay_filter.check_and_add(pkt_seq) {
                            debug!("[P2P Hole Punch] Dropping replayed packet with seq {} from {}", pkt_seq, src);
                            continue;
                        }

                        if cmd == "PEER_PUNCH" {
                            if current_step == 1 {
                                info!(
                                    "[P2P Hole Punch] [Progress: Round {}/{}] STEP 1/3: Received direct probe from {}. Outbound NAT hole confirmed! Replying with PEER_PUNCH_ACK.",
                                    round, max_rounds, src
                                );
                                println!(
                                    "[P2P Hole Punch] [Progress: Round {}/{}] STEP 1/3: Received direct probe from {}. Outbound NAT hole confirmed! Replying with PEER_PUNCH_ACK.",
                                    round, max_rounds, src
                                );
                                current_step = 2;
                            }
                        } else if cmd == "PEER_PUNCH_ACK" {
                            info!(
                                "[P2P Hole Punch] [Progress: Round {}/{}] STEP 2/3: Received PEER_PUNCH_ACK from {}. Bidirectional NAT mapping confirmed! Replying with PEER_PUNCH_ACK_ACK.",
                                round, max_rounds, src
                            );
                            println!(
                                "[P2P Hole Punch] [Progress: Round {}/{}] STEP 2/3: Received PEER_PUNCH_ACK from {}. Bidirectional NAT mapping confirmed! Replying with PEER_PUNCH_ACK_ACK.",
                                round, max_rounds, src
                            );
                            current_step = 3;
                            punched = true;
                        } else if cmd == "PEER_PUNCH_ACK_ACK" {
                            info!(
                                "[P2P Hole Punch] [Progress: Round {}/{}] STEP 3/3: Received PEER_PUNCH_ACK_ACK from {}. 3-way handshake COMPLETE!",
                                round, max_rounds, src
                            );
                            println!(
                                "[P2P Hole Punch] [Progress: Round {}/{}] STEP 3/3: Received PEER_PUNCH_ACK_ACK from {}. 3-way handshake COMPLETE!",
                                round, max_rounds, src
                            );
                            punched = true;
                            for _ in 0..3 {
                                let a_seq = next_seq();
                                let a_payload = format!("PEER_PUNCH_ACK_ACK:{}", a_seq);
                                let a_hmac = compute_auth(passcode, &a_payload);
                                let a_msg = format!("PEER_PUNCH_ACK_ACK {} {}", a_seq, a_hmac);
                                socket.send_to(a_msg.as_bytes(), peer_addr)?;
                            }
                            break;
                        }

                        if src != peer_addr {
                            info!(
                                "[P2P Hole Punch] Discovered NAT reflexive endpoint: updating peer address from {} to {}",
                                peer_addr, src
                            );
                            println!(
                                "[P2P Hole Punch] Discovered NAT reflexive endpoint: updating peer address from {} to {}",
                                peer_addr, src
                            );
                            peer_addr = src;
                        }
                    } else if src.ip() == peer_addr.ip() && len > 0 && !parts.is_empty() && !parts[0].starts_with("PEER_") {
                        // Received early data (e.g. QUIC Initial from peer who completed hole punch)
                        debug!(
                            "[P2P Hole Punch] Received data packet (len={}) from peer {} during hole punch.",
                            len, src
                        );
                        punched = true;
                        break;
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Expected read timeout
                }
                Err(e) => {
                    debug!("[P2P Hole Punch] recv error: {}", e);
                }
            }
        }

        if punched {
            info!(
                "[P2P Hole Punch SUCCESS] UDP hole punching successfully established with peer {} on Round {}/{}!",
                peer_addr, round, max_rounds
            );
            println!(
                "[P2P Hole Punch SUCCESS] UDP hole punching successfully established with peer {} on Round {}/{}!",
                peer_addr, round, max_rounds
            );
            socket.set_read_timeout(None)?;
            return Ok(peer_addr);
        }

        if round < max_rounds {
            warn!(
                "[P2P Hole Punch] Round {}/{} timed out without confirming bidirectional path with {}. Retrying Round {}/{}...",
                round, max_rounds, peer_addr, round + 1, max_rounds
            );
            println!(
                "[P2P Hole Punch] Round {}/{} timed out without confirming bidirectional path with {}. Retrying Round {}/{}...",
                round, max_rounds, peer_addr, round + 1, max_rounds
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    error!(
        "[P2P Hole Punch ERROR] Failed to establish UDP hole punch with peer {} after {} rounds. Giving up.",
        peer_addr, max_rounds
    );
    eprintln!(
        "[P2P Hole Punch ERROR] Failed to establish UDP hole punch with peer {} after {} rounds. Giving up.",
        peer_addr, max_rounds
    );

    Err(format!(
        "UDP hole punching failed to reach peer {} after {} rounds",
        peer_addr, max_rounds
    )
    .into())
}

pub fn run_server_p2p_handshake(
    rendezvous_addr: SocketAddr,
    name: &str,
    rendezvous_passcode: &str,
    server_passcode: &str,
    tcp_port: u16,
) -> Result<UdpSocket, Box<dyn std::error::Error>> {
    let bind_addr = match rendezvous_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = [0; 1024];

    // 1. Register with Rendezvous Server using rendezvous_passcode
    println!(
        "Registering at Rendezvous Server {} as '{}' (TCP Port: {}, Status: IDLE)...",
        rendezvous_addr, name, tcp_port
    );
    let mut reg_ok = false;
    let last_err = String::new();
    for _ in 0..5 {
        let seq = next_seq();
        let payload = format!("REG:{}:{}:IDLE:{}:{}", name, tcp_port, server_passcode, seq);
        let hmac = compute_auth(rendezvous_passcode, &payload);
        let reg_msg = format!("REG {} {} IDLE {} {} {}", name, tcp_port, server_passcode, seq, hmac);

        socket.send_to(reg_msg.as_bytes(), rendezvous_addr)?;
        match socket.recv_from(&mut buf) {
            Ok((len, src)) if src == rendezvous_addr => {
                let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                let parts: Vec<&str> = reply.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "REG_OK" {
                    let resp_seq = parts[1];
                    let resp_hmac = parts[2];
                    let expected_payload = format!("REG_OK:{}", resp_seq);
                    if verify_auth(rendezvous_passcode, &expected_payload, resp_hmac) {
                        reg_ok = true;
                        break;
                    } else {
                        return Err("Authentication failed on REG_OK reply from Rendezvous Server".into());
                    }
                } else if parts.len() >= 2 && parts[0] == "ERR" {
                    return Err(format!("Rendezvous Server rejected registration: {}", reply).into());
                }
            }
            _ => {}
        }
    }

    if !reg_ok {
        let err_detail = if last_err.is_empty() {
            "timeout or invalid rendezvous passcode".to_string()
        } else {
            last_err
        };
        error!(
            "[P2P Server ERROR] Failed to register at Rendezvous Server {} ({}). Giving up.",
            rendezvous_addr, err_detail
        );
        eprintln!(
            "[P2P Server ERROR] Failed to register at Rendezvous Server {} ({}). Giving up.",
            rendezvous_addr, err_detail
        );
        return Err(format!("Failed to register at Rendezvous Server: {}", err_detail).into());
    }
    println!("Registration successful at Rendezvous Server.");

    // 2. Wait for authenticated PUNCH control request (signed with server_passcode)
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    println!("Waiting for peer connection (sending authenticated keep-alives every 10s)...");
    let peer_addr = loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if src == rendezvous_addr {
                    let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                    let parts: Vec<&str> = reply.split_whitespace().collect();
                    if parts.len() >= 5 && parts[0] == "PUNCH" {
                        let client_addr_str = parts[1];
                        let role = parts[2];
                        let seq = parts[3];
                        let hmac = parts[4];
                        let expected_payload = format!("PUNCH:{}:{}:{}", client_addr_str, role, seq);
                        if verify_auth(server_passcode, &expected_payload, hmac) {
                            if role == "passive" {
                                let addr: SocketAddr = client_addr_str.parse()?;
                                break addr;
                            }
                        } else {
                            warn!("Received unauthenticated PUNCH packet from Rendezvous Server, dropping.");
                        }
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout, send keep-alive
                let _ = send_server_keepalive(
                    &socket,
                    rendezvous_addr,
                    name,
                    tcp_port,
                    "IDLE",
                    server_passcode,
                    rendezvous_passcode,
                );
            }
            Err(e) => {
                error!("[P2P Server ERROR] Socket error while waiting for connection: {}. Giving up.", e);
                eprintln!("[P2P Server ERROR] Socket error while waiting for connection: {}. Giving up.", e);
                return Err(e.into());
            }
        }
    };

    // 3. Hole Punching Phase using server_passcode
    info!(
        "[P2P Server] Received authenticated connection request from {}. Starting UDP hole punching...",
        peer_addr
    );
    let final_peer_addr = match perform_hole_punching(&socket, peer_addr, server_passcode) {
        Ok(addr) => addr,
        Err(e) => {
            error!(
                "[P2P Server ERROR] Hole punching failed with client {}: {}. Giving up.",
                peer_addr, e
            );
            eprintln!(
                "[P2P Server ERROR] Hole punching failed with client {}: {}. Giving up.",
                peer_addr, e
            );
            return Err(e);
        }
    };

    info!(
        "[P2P Server] UDP hole punching succeeded with peer {}",
        final_peer_addr
    );
    println!(
        "[P2P Server] UDP hole punching succeeded with peer {}",
        final_peer_addr
    );

    socket.set_read_timeout(None)?;
    Ok(socket)
}

pub fn run_client_p2p_handshake(
    rendezvous_addr: SocketAddr,
    server_passcode: &str,
    target_tcp_port: u16,
) -> Result<(UdpSocket, SocketAddr, String), Box<dyn std::error::Error>> {
    let max_handshake_attempts = 3;

    for attempt in 1..=max_handshake_attempts {
        info!(
            "[P2P Client] Handshake attempt {}/{}: Connecting to Rendezvous Server {} for target TCP port {}...",
            attempt, max_handshake_attempts, rendezvous_addr, target_tcp_port
        );
        println!(
            "[P2P Client] Handshake attempt {}/{}: Connecting to Rendezvous Server {} for target TCP port {}...",
            attempt, max_handshake_attempts, rendezvous_addr, target_tcp_port
        );

        let bind_addr = match rendezvous_addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = match UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                if attempt == max_handshake_attempts {
                    error!("[P2P Client ERROR] Failed to bind local UDP socket: {}. Giving up.", e);
                    eprintln!("[P2P Client ERROR] Failed to bind local UDP socket: {}. Giving up.", e);
                    return Err(e.into());
                }
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;

        let mut buf = [0; 1024];

        // Send CONN to Rendezvous Server with target_tcp_port and server_passcode HMAC
        let mut peer_addr = None;
        let mut target_name = String::new();
        let mut last_err = String::new();

        for _ in 0..5 {
            let seq = next_seq();
            let payload = format!("CONN:{}:{}", target_tcp_port, seq);
            let hmac = compute_auth(server_passcode, &payload);
            let conn_msg = format!("CONN {} {} {}", target_tcp_port, seq, hmac);

            socket.send_to(conn_msg.as_bytes(), rendezvous_addr)?;
            match socket.recv_from(&mut buf) {
                Ok((len, src)) if src == rendezvous_addr => {
                    let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                    let parts: Vec<&str> = reply.split_whitespace().collect();
                    if parts.len() >= 6 && parts[0] == "PUNCH" {
                        let peer_addr_str = parts[1];
                        let role = parts[2];
                        let srv_name = parts[3];
                        let resp_seq = parts[4];
                        let resp_hmac = parts[5];
                        let expected_payload = format!("PUNCH:{}:{}:{}:{}", peer_addr_str, role, srv_name, resp_seq);
                        if verify_auth(server_passcode, &expected_payload, resp_hmac) && role == "active" {
                            let addr: SocketAddr = peer_addr_str.parse()?;
                            peer_addr = Some(addr);
                            target_name = srv_name.to_string();
                            break;
                        }
                    } else if parts.len() >= 2 && parts[0] == "ERR" {
                        last_err = reply.to_string();
                        warn!("[P2P Client] Rendezvous Server rejected connection: {}", reply);
                        println!("[P2P Client] Rendezvous Server rejected connection: {}", reply);
                        if reply.contains("Authentication failed") || reply.contains("No server registered") {
                            error!("[P2P Client ERROR] Connection rejected: {}. Giving up.", reply);
                            eprintln!("[P2P Client ERROR] Connection rejected: {}. Giving up.", reply);
                            return Err(reply.into());
                        }
                        break;
                    }
                }
                _ => {}
            }
        }

        let peer_addr = match peer_addr {
            Some(addr) => addr,
            None => {
                if !last_err.is_empty() && (last_err.contains("Authentication failed") || last_err.contains("No server registered")) {
                    return Err(last_err.into());
                }
                if attempt < max_handshake_attempts {
                    warn!(
                        "[P2P Client] Attempt {}/{} timed out waiting for PUNCH signal from Rendezvous Server ({}). Retrying in 1s...",
                        attempt, max_handshake_attempts, if last_err.is_empty() { "timeout" } else { &last_err }
                    );
                    println!(
                        "[P2P Client] Attempt {}/{} timed out waiting for PUNCH signal from Rendezvous Server ({}). Retrying in 1s...",
                        attempt, max_handshake_attempts, if last_err.is_empty() { "timeout" } else { &last_err }
                    );
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                } else {
                    error!(
                        "[P2P Client ERROR] Failed to connect via Rendezvous Server after {} attempts ({}). Giving up.",
                        max_handshake_attempts, if last_err.is_empty() { "timeout" } else { &last_err }
                    );
                    eprintln!(
                        "[P2P Client ERROR] Failed to connect via Rendezvous Server after {} attempts ({}). Giving up.",
                        max_handshake_attempts, if last_err.is_empty() { "timeout" } else { &last_err }
                    );
                    return Err(format!("Failed to connect via Rendezvous Server: {}", if last_err.is_empty() { "timeout" } else { &last_err }).into());
                }
            }
        };

        // Hole Punching Phase with server_passcode
        info!("[P2P Client] Starting UDP hole punching to server endpoint {}...", peer_addr);
        println!("[P2P Client] Starting UDP hole punching to server endpoint {}...", peer_addr);
        match perform_hole_punching(&socket, peer_addr, server_passcode) {
            Ok(final_peer_addr) => {
                info!(
                    "[P2P Client] UDP hole punching succeeded with peer {}",
                    final_peer_addr
                );
                println!(
                    "[P2P Client] UDP hole punching succeeded with peer {}",
                    final_peer_addr
                );
                socket.set_read_timeout(None)?;
                return Ok((socket, final_peer_addr, target_name));
            }
            Err(e) => {
                if attempt < max_handshake_attempts {
                    warn!(
                        "[P2P Client] Hole punching attempt {}/{} failed with peer {}: {}. Retrying full handshake in 1s...",
                        attempt, max_handshake_attempts, peer_addr, e
                    );
                    println!(
                        "[P2P Client] Hole punching attempt {}/{} failed with peer {}: {}. Retrying full handshake in 1s...",
                        attempt, max_handshake_attempts, peer_addr, e
                    );
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                } else {
                    error!(
                        "[P2P Client ERROR] UDP hole punching failed with peer {} after {} attempts. Giving up.",
                        peer_addr, max_handshake_attempts
                    );
                    eprintln!(
                        "[P2P Client ERROR] UDP hole punching failed with peer {} after {} attempts. Giving up.",
                        peer_addr, max_handshake_attempts
                    );
                    return Err(e);
                }
            }
        }
    }

    error!(
        "[P2P Client ERROR] P2P handshake failed for target TCP port {} after {} attempts. Giving up.",
        target_tcp_port, max_handshake_attempts
    );
    eprintln!(
        "[P2P Client ERROR] P2P handshake failed for target TCP port {} after {} attempts. Giving up.",
        target_tcp_port, max_handshake_attempts
    );
    Err("P2P client handshake failed after retries".into())
}

pub fn send_server_keepalive(
    socket: &UdpSocket,
    rendezvous_addr: SocketAddr,
    name: &str,
    tcp_port: u16,
    status: &str,
    server_passcode: &str,
    rendezvous_passcode: &str,
) -> io::Result<()> {
    let seq = next_seq();
    let payload = format!("REG:{}:{}:{}:{}:{}", name, tcp_port, status, server_passcode, seq);
    let hmac = compute_auth(rendezvous_passcode, &payload);
    let reg_msg = format!("REG {} {} {} {} {} {}", name, tcp_port, status, server_passcode, seq, hmac);
    socket.send_to(reg_msg.as_bytes(), rendezvous_addr)?;
    Ok(())
}

pub fn send_server_status(
    socket: &UdpSocket,
    rendezvous_addr: SocketAddr,
    name: &str,
    status: &str,
    rendezvous_passcode: &str,
) -> io::Result<()> {
    let seq = next_seq();
    let payload = format!("STATUS:{}:{}:{}", name, status, seq);
    let hmac = compute_auth(rendezvous_passcode, &payload);
    let status_msg = format!("STATUS {} {} {} {}", name, status, seq, hmac);
    socket.send_to(status_msg.as_bytes(), rendezvous_addr)?;
    Ok(())
}

pub fn reconnect_client_p2p_handshake(
    socket: &UdpSocket,
    rendezvous_addr: SocketAddr,
    server_passcode: &str,
    target_tcp_port: u16,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let max_reconnect_attempts = 3;

    for attempt in 1..=max_reconnect_attempts {
        info!(
            "[P2P Reconnect] Attempt {}/{}: Reporting unreachable socket to Rendezvous Server {} for TCP Port {}...",
            attempt, max_reconnect_attempts, rendezvous_addr, target_tcp_port
        );
        println!(
            "[P2P Reconnect] Attempt {}/{}: Reporting unreachable socket to Rendezvous Server {} for TCP Port {}...",
            attempt, max_reconnect_attempts, rendezvous_addr, target_tcp_port
        );

        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut buf = [0; 1024];
        let mut peer_addr = None;
        let mut last_err = String::new();

        for _ in 0..5 {
            let seq = next_seq();
            let payload = format!("RESET:{}:{}", target_tcp_port, seq);
            let hmac = compute_auth(server_passcode, &payload);
            let reset_msg = format!("RESET {} {} {}", target_tcp_port, seq, hmac);

            socket.send_to(reset_msg.as_bytes(), rendezvous_addr)?;
            match socket.recv_from(&mut buf) {
                Ok((len, src)) if src == rendezvous_addr => {
                    let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                    let parts: Vec<&str> = reply.split_whitespace().collect();
                    if parts.len() >= 6 && parts[0] == "PUNCH" {
                        let peer_addr_str = parts[1];
                        let role = parts[2];
                        let srv_name = parts[3];
                        let resp_seq = parts[4];
                        let resp_hmac = parts[5];
                        let expected_payload = format!("PUNCH:{}:{}:{}:{}", peer_addr_str, role, srv_name, resp_seq);
                        if verify_auth(server_passcode, &expected_payload, resp_hmac) && role == "active" {
                            let addr: SocketAddr = peer_addr_str.parse()?;
                            peer_addr = Some(addr);
                            break;
                        }
                    } else if parts.len() >= 2 && parts[0] == "ERR" {
                        last_err = reply.to_string();
                        warn!("[P2P Reconnect] Reset request rejected: {}", reply);
                        if reply.contains("Authentication failed") || reply.contains("No server registered") {
                            return Err(reply.into());
                        }
                    }
                }
                _ => {}
            }
        }

        let peer_addr = match peer_addr {
            Some(addr) => addr,
            None => {
                if attempt < max_reconnect_attempts {
                    warn!(
                        "[P2P Reconnect] Attempt {}/{} timed out waiting for PUNCH signal from Rendezvous Server ({}). Retrying in 1s...",
                        attempt, max_reconnect_attempts, if last_err.is_empty() { "timeout" } else { &last_err }
                    );
                    println!(
                        "[P2P Reconnect] Attempt {}/{} timed out waiting for PUNCH signal from Rendezvous Server ({}). Retrying in 1s...",
                        attempt, max_reconnect_attempts, if last_err.is_empty() { "timeout" } else { &last_err }
                    );
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                } else {
                    error!(
                        "[P2P Reconnect ERROR] Failed to reconnect via Rendezvous Server after {} attempts ({}). Giving up.",
                        max_reconnect_attempts, if last_err.is_empty() { "timeout" } else { &last_err }
                    );
                    eprintln!(
                        "[P2P Reconnect ERROR] Failed to reconnect via Rendezvous Server after {} attempts ({}). Giving up.",
                        max_reconnect_attempts, if last_err.is_empty() { "timeout" } else { &last_err }
                    );
                    return Err(format!("Failed to reconnect via Rendezvous Server: {}", if last_err.is_empty() { "timeout" } else { &last_err }).into());
                }
            }
        };

        info!(
            "[P2P Reconnect] Starting UDP hole punching to server endpoint {}...",
            peer_addr
        );
        println!(
            "[P2P Reconnect] Starting UDP hole punching to server endpoint {}...",
            peer_addr
        );

        match perform_hole_punching(socket, peer_addr, server_passcode) {
            Ok(final_peer_addr) => {
                info!(
                    "[P2P Reconnect] UDP hole punching succeeded with peer {}",
                    final_peer_addr
                );
                println!(
                    "[P2P Reconnect] UDP hole punching succeeded with peer {}",
                    final_peer_addr
                );
                socket.set_read_timeout(None)?;
                return Ok(final_peer_addr);
            }
            Err(e) => {
                if attempt < max_reconnect_attempts {
                    warn!(
                        "[P2P Reconnect] Hole punching attempt {}/{} failed with peer {}: {}. Retrying in 1s...",
                        attempt, max_reconnect_attempts, peer_addr, e
                    );
                    println!(
                        "[P2P Reconnect] Hole punching attempt {}/{} failed with peer {}: {}. Retrying in 1s...",
                        attempt, max_reconnect_attempts, peer_addr, e
                    );
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                } else {
                    error!(
                        "[P2P Reconnect ERROR] Failed to restore UDP hole punch to server for TCP Port {} ({}) after {} attempts. Giving up.",
                        target_tcp_port, peer_addr, max_reconnect_attempts
                    );
                    eprintln!(
                        "[P2P Reconnect ERROR] Failed to restore UDP hole punch to server for TCP Port {} ({}) after {} attempts. Giving up.",
                        target_tcp_port, peer_addr, max_reconnect_attempts
                    );
                    return Err(e);
                }
            }
        }
    }

    error!(
        "[P2P Reconnect ERROR] Reconnect failed for TCP Port {} after {} attempts. Giving up.",
        target_tcp_port, max_reconnect_attempts
    );
    eprintln!(
        "[P2P Reconnect ERROR] Reconnect failed for TCP Port {} after {} attempts. Giving up.",
        target_tcp_port, max_reconnect_attempts
    );
    Err("P2P client reconnect failed after retries".into())
}

pub fn server_handle_reconnect_punch(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    rendezvous_addr: SocketAddr,
    name: &str,
    tcp_port: u16,
    server_passcode: &str,
    rendezvous_passcode: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    info!(
        "[P2P Server Reconnect] Received request for client {}. Starting UDP hole punching...",
        client_addr
    );
    println!(
        "[P2P Server Reconnect] Received request for client {}. Starting UDP hole punching...",
        client_addr
    );
    let final_peer_addr = match perform_hole_punching(socket, client_addr, server_passcode) {
        Ok(addr) => addr,
        Err(e) => {
            error!(
                "[P2P Server Reconnect ERROR] Hole punching failed with client {}: {}. Giving up.",
                client_addr, e
            );
            eprintln!(
                "[P2P Server Reconnect ERROR] Hole punching failed with client {}: {}. Giving up.",
                client_addr, e
            );
            return Err(e);
        }
    };

    info!(
        "[P2P Server Reconnect] UDP hole punching succeeded with peer {}",
        final_peer_addr
    );
    println!(
        "[P2P Server Reconnect] UDP hole punching succeeded with peer {}",
        final_peer_addr
    );

    let _ = send_server_keepalive(
        socket,
        rendezvous_addr,
        name,
        tcp_port,
        "BUSY",
        server_passcode,
        rendezvous_passcode,
    );

    socket.set_read_timeout(None)?;
    Ok(final_peer_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_computation_and_verification() {
        let passcode = "super_secret";
        let payload = "REG:srv1:8080:IDLE:pass1:123456";
        let hmac = compute_auth(passcode, payload);
        assert!(!hmac.is_empty());
        assert!(verify_auth(passcode, payload, &hmac));
        assert!(!verify_auth("wrong_passcode", payload, &hmac));
        assert!(!verify_auth(passcode, "different_payload", &hmac));
    }

    #[test]
    fn test_replay_filter_detection() {
        let mut filter = ReplayFilter::new();
        let seq1 = next_seq();
        let seq2 = next_seq();

        // First presentation of sequences succeeds
        assert!(filter.check_and_add(seq1));
        assert!(filter.check_and_add(seq2));

        // Replay of same sequence must be rejected
        assert!(!filter.check_and_add(seq1));
        assert!(!filter.check_and_add(seq2));

        // Ancient sequence (more than 120s ago) must be rejected
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let ancient_seq = ((now_ms - 200_000) << 10) | 1;
        assert!(!filter.check_and_add(ancient_seq));

        // Future sequence (> 120s in future) must be rejected
        let future_seq = ((now_ms + 200_000) << 10) | 1;
        assert!(!filter.check_and_add(future_seq));
    }
}