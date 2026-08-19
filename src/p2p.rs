use log::{debug, error, info, warn};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub use crate::auth::{compute_auth, derive_tunnel_id, next_seq, verify_auth, ReplayFilter};
use crate::protocol::{
    ClientConn, ClientReset, PeerProbe, PunchSignal, RegOk, ServerReg, ServerStatusMsg,
};

/// Performs UDP hole punching between two peers with multi-round retries, progress logging, and replay-protected HMAC authentication.
///
/// Workflow:
/// - Round 1..=3: Sends signed UDP probes (`PEER_PUNCH`, `PEER_PUNCH_ACK`, `PEER_PUNCH_ACK_ACK`).
/// - Handles symmetric NAT port changes dynamically.
/// - Returns the final learned `SocketAddr` of the remote peer.
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
            let probe_msg = match current_step {
                1 => PeerProbe::new_punch(passcode),
                2 => PeerProbe::new_ack(passcode),
                _ => PeerProbe::new_ack_ack(passcode),
            };
            socket.send_to(probe_msg.as_bytes(), peer_addr)?;

            debug!(
                "[P2P Hole Punch] [Round {}/{} Probe #{}] Sent step {} to {}",
                round, max_rounds, attempt, current_step, peer_addr
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
                    if src.ip() == peer_addr.ip() {
                        if let Some(probe) = PeerProbe::parse(text) {
                            if !probe.verify(passcode) {
                                debug!("[P2P Hole Punch] Dropping probe with invalid HMAC from {}", src);
                                continue;
                            }
                            if !replay_filter.check_and_add(probe.seq()) {
                                debug!(
                                    "[P2P Hole Punch] Dropping replayed probe with seq {} from {}",
                                    probe.seq(), src
                                );
                                continue;
                            }

                            match probe {
                                PeerProbe::Punch(..) => {
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
                                }
                                PeerProbe::Ack(..) => {
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
                                }
                                PeerProbe::AckAck(..) => {
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
                                        let final_ack = PeerProbe::new_ack_ack(passcode);
                                        socket.send_to(final_ack.as_bytes(), peer_addr)?;
                                    }
                                    break;
                                }
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
                        } else if len > 0 && !text.starts_with("PEER_") {
                            // Early data from peer (e.g. QUIC Initial packet)
                            debug!(
                                "[P2P Hole Punch] Received data packet (len={}) from peer {} during hole punch.",
                                len, src
                            );
                            punched = true;
                            break;
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Expected read timeout between probes
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

/// Orchestrates P2P registration and handshake for a `quic-to-tcp` server.
pub fn run_server_p2p_handshake(
    rendezvous_addr: SocketAddr,
    tunnel_code: &str,
    tcp_port: u16,
) -> Result<(UdpSocket, String), Box<dyn std::error::Error>> {
    let tunnel_id = derive_tunnel_id(tunnel_code);
    let bind_addr = match rendezvous_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = [0; 1024];

    // 1. Register with Rendezvous Server using tunnel_code
    println!(
        "Registering at Rendezvous Server {} (Tunnel ID: {}, Target Port: {}, Status: IDLE)...",
        rendezvous_addr, tunnel_id, tcp_port
    );
    let mut reg_ok = false;
    for _ in 0..5 {
        let reg_msg = ServerReg::new_signed(&tunnel_id, tcp_port, "IDLE", tunnel_code);
        socket.send_to(reg_msg.as_bytes(), rendezvous_addr)?;

        match socket.recv_from(&mut buf) {
            Ok((len, src)) if src == rendezvous_addr => {
                let reply = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                if let Some(ok) = RegOk::parse(reply) {
                    if ok.verify(tunnel_code) {
                        reg_ok = true;
                        break;
                    } else {
                        return Err("Authentication failed on REG_OK reply from Rendezvous Server".into());
                    }
                } else if reply.starts_with("ERR") {
                    return Err(format!("Rendezvous Server rejected registration: {}", reply).into());
                }
            }
            _ => {}
        }
    }

    if !reg_ok {
        error!(
            "[P2P Server ERROR] Failed to register at Rendezvous Server {} (timeout or rejected). Giving up.",
            rendezvous_addr
        );
        eprintln!(
            "[P2P Server ERROR] Failed to register at Rendezvous Server {} (timeout or rejected). Giving up.",
            rendezvous_addr
        );
        return Err("Failed to register at Rendezvous Server: timeout or rejected".into());
    }
    println!("Registration successful at Rendezvous Server.");

    // 2. Wait for authenticated PUNCH signal from Rendezvous Server
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    println!("Waiting for peer connection (sending authenticated keep-alives every 10s)...");
    let peer_addr = loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) if src == rendezvous_addr => {
                let reply = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                if let Some(signal) = PunchSignal::parse(reply) {
                    if signal.verify(tunnel_code) {
                        if let PunchSignal::Passive { client_addr, .. } = signal {
                            break client_addr;
                        }
                    } else {
                        warn!("Received unauthenticated PUNCH packet from Rendezvous Server, dropping.");
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout, send authenticated keep-alive
                let _ = send_server_keepalive(
                    &socket,
                    rendezvous_addr,
                    &tunnel_id,
                    tcp_port,
                    "IDLE",
                    tunnel_code,
                );
            }
            Err(e) => {
                error!("[P2P Server ERROR] Socket error while waiting for connection: {}. Giving up.", e);
                eprintln!("[P2P Server ERROR] Socket error while waiting for connection: {}. Giving up.", e);
                return Err(e.into());
            }
            _ => {}
        }
    };

    // 3. Hole Punching Phase with client
    info!(
        "[P2P Server] Received authenticated connection request from {}. Starting UDP hole punching...",
        peer_addr
    );
    let final_peer_addr = match perform_hole_punching(&socket, peer_addr, tunnel_code) {
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
    Ok((socket, tunnel_id))
}

/// Orchestrates P2P connection request and handshake for a `tcp-to-quic` client.
pub fn run_client_p2p_handshake(
    rendezvous_addr: SocketAddr,
    tunnel_code: &str,
) -> Result<(UdpSocket, SocketAddr, String), Box<dyn std::error::Error>> {
    let tunnel_id = derive_tunnel_id(tunnel_code);
    let max_handshake_attempts = 3;

    for attempt in 1..=max_handshake_attempts {
        info!(
            "[P2P Client] Handshake attempt {}/{}: Connecting to Rendezvous Server {} for Tunnel ID {}...",
            attempt, max_handshake_attempts, rendezvous_addr, tunnel_id
        );
        println!(
            "[P2P Client] Handshake attempt {}/{}: Connecting to Rendezvous Server {} for Tunnel ID {}...",
            attempt, max_handshake_attempts, rendezvous_addr, tunnel_id
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
        let mut peer_addr = None;
        let mut last_err = String::new();

        for _ in 0..5 {
            let conn_msg = ClientConn::new_signed(&tunnel_id, tunnel_code);
            socket.send_to(conn_msg.as_bytes(), rendezvous_addr)?;

            match socket.recv_from(&mut buf) {
                Ok((len, src)) if src == rendezvous_addr => {
                    let reply = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                    if let Some(signal) = PunchSignal::parse(reply) {
                        if signal.verify(tunnel_code) {
                            if let PunchSignal::Active { server_addr, .. } = signal {
                                peer_addr = Some(server_addr);
                                break;
                            }
                        }
                    } else if reply.starts_with("ERR") {
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

        // Hole Punching Phase with tunnel_code
        info!("[P2P Client] Starting UDP hole punching to server endpoint {}...", peer_addr);
        println!("[P2P Client] Starting UDP hole punching to server endpoint {}...", peer_addr);
        match perform_hole_punching(&socket, peer_addr, tunnel_code) {
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
                return Ok((socket, final_peer_addr, tunnel_id));
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
        "[P2P Client ERROR] P2P handshake failed for Tunnel ID {} after {} attempts. Giving up.",
        tunnel_id, max_handshake_attempts
    );
    eprintln!(
        "[P2P Client ERROR] P2P handshake failed for Tunnel ID {} after {} attempts. Giving up.",
        tunnel_id, max_handshake_attempts
    );
    Err("P2P client handshake failed after retries".into())
}

/// Sends a periodic authenticated registration keep-alive packet to `rendezvous-server`.
pub fn send_server_keepalive(
    socket: &UdpSocket,
    rendezvous_addr: SocketAddr,
    tunnel_id: &str,
    tcp_port: u16,
    status: &str,
    tunnel_code: &str,
) -> io::Result<()> {
    let reg_msg = ServerReg::new_signed(tunnel_id, tcp_port, status, tunnel_code);
    socket.send_to(reg_msg.as_bytes(), rendezvous_addr)?;
    Ok(())
}

/// Sends an authenticated status transition (IDLE / BUSY) update to `rendezvous-server`.
pub fn send_server_status(
    socket: &UdpSocket,
    rendezvous_addr: SocketAddr,
    tunnel_id: &str,
    status: &str,
    tunnel_code: &str,
) -> io::Result<()> {
    let status_msg = ServerStatusMsg::new_signed(tunnel_id, status, tunnel_code);
    socket.send_to(status_msg.as_bytes(), rendezvous_addr)?;
    Ok(())
}

/// Re-negotiates UDP hole punching after an existing connection has been dropped or reset.
pub fn reconnect_client_p2p_handshake(
    socket: &UdpSocket,
    rendezvous_addr: SocketAddr,
    tunnel_code: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let tunnel_id = derive_tunnel_id(tunnel_code);
    let max_reconnect_attempts = 3;

    for attempt in 1..=max_reconnect_attempts {
        info!(
            "[P2P Reconnect] Attempt {}/{}: Reporting unreachable socket to Rendezvous Server {} for Tunnel ID {}...",
            attempt, max_reconnect_attempts, rendezvous_addr, tunnel_id
        );
        println!(
            "[P2P Reconnect] Attempt {}/{}: Reporting unreachable socket to Rendezvous Server {} for Tunnel ID {}...",
            attempt, max_reconnect_attempts, rendezvous_addr, tunnel_id
        );

        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut buf = [0; 1024];
        let mut peer_addr = None;
        let mut last_err = String::new();

        for _ in 0..5 {
            let reset_msg = ClientReset::new_signed(&tunnel_id, tunnel_code);
            socket.send_to(reset_msg.as_bytes(), rendezvous_addr)?;

            match socket.recv_from(&mut buf) {
                Ok((len, src)) if src == rendezvous_addr => {
                    let reply = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                    if let Some(signal) = PunchSignal::parse(reply) {
                        if signal.verify(tunnel_code) {
                            if let PunchSignal::Active { server_addr, .. } = signal {
                                peer_addr = Some(server_addr);
                                break;
                            }
                        }
                    } else if reply.starts_with("ERR") {
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

        match perform_hole_punching(socket, peer_addr, tunnel_code) {
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
                        "[P2P Reconnect ERROR] Failed to restore UDP hole punch to server ({}) after {} attempts. Giving up.",
                        peer_addr, max_reconnect_attempts
                    );
                    eprintln!(
                        "[P2P Reconnect ERROR] Failed to restore UDP hole punch to server ({}) after {} attempts. Giving up.",
                        peer_addr, max_reconnect_attempts
                    );
                    return Err(e);
                }
            }
        }
    }

    error!(
        "[P2P Reconnect ERROR] Reconnect failed for Tunnel ID {} after {} attempts. Giving up.",
        tunnel_id, max_reconnect_attempts
    );
    eprintln!(
        "[P2P Reconnect ERROR] Reconnect failed for Tunnel ID {} after {} attempts. Giving up.",
        tunnel_id, max_reconnect_attempts
    );
    Err("P2P client reconnect failed after retries".into())
}

/// Handles a reconnect punch request on the server side.
pub fn server_handle_reconnect_punch(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    rendezvous_addr: SocketAddr,
    tunnel_id: &str,
    tcp_port: u16,
    tunnel_code: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    info!(
        "[P2P Server Reconnect] Received request for client {}. Starting UDP hole punching...",
        client_addr
    );
    println!(
        "[P2P Server Reconnect] Received request for client {}. Starting UDP hole punching...",
        client_addr
    );
    let final_peer_addr = match perform_hole_punching(socket, client_addr, tunnel_code) {
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
        tunnel_id,
        tcp_port,
        "BUSY",
        tunnel_code,
    );

    socket.set_read_timeout(None)?;
    Ok(final_peer_addr)
}
