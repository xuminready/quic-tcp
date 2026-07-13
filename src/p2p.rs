use log::{debug, info};
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Performs UDP hole punching between two peers.
/// Returns the final learned SocketAddr of the peer.
pub fn perform_hole_punching(
    socket: &UdpSocket,
    peer_addr: SocketAddr,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut punched = false;
    let mut peer_addr = peer_addr; // Make mutable to allow port learning
    let mut buf = [0; 1024];

    let mut state_msg = b"PEER_PUNCH".as_slice();
    let mut ack_ack_sends = 0;

    for _ in 0..30 {
        // Try for 3 seconds
        socket.send_to(state_msg, peer_addr)?;

        if punched {
            ack_ack_sends += 1;
            if ack_ack_sends >= 3 {
                break;
            }
        }

        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let msg = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                if src.ip() == peer_addr.ip() {
                    if msg == "PEER_PUNCH" {
                        if state_msg == b"PEER_PUNCH" {
                            info!("Received PUNCH from peer. Sending ACK.");
                            state_msg = b"PEER_PUNCH_ACK";
                        }
                    } else if msg == "PEER_PUNCH_ACK" {
                        info!("Received ACK from peer. Stream is bi-directional. Sending ACK_ACK.");
                        state_msg = b"PEER_PUNCH_ACK_ACK";
                        punched = true;
                    } else if msg == "PEER_PUNCH_ACK_ACK" {
                        info!("Received ACK_ACK from peer. Peer is ready.");
                        punched = true;
                        // Send one final ACK_ACK to ensure the peer exits as well
                        socket.send_to(b"PEER_PUNCH_ACK_ACK", peer_addr)?;
                        break;
                    }

                    if src != peer_addr {
                        info!(
                            "Peer port changed from {} to {}. Updating peer address.",
                            peer_addr.port(),
                            src.port()
                        );
                        peer_addr = src;
                    }
                } else {
                    debug!(
                        "Received packet from unexpected source {} during hole punching: '{}'",
                        src, msg
                    );
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Expected timeout
            }
            Err(e) => {
                debug!("Error during hole punching recv: {}", e);
            }
        }
    }

    if !punched {
        info!("Hole punching completed without explicit peer ack, transitioning...");
    }

    Ok(peer_addr)
}

pub fn run_server_p2p_handshake(
    rendezvous_addr: SocketAddr,
    name: &str,
    cap: &str,
    loc: &str,
) -> Result<UdpSocket, Box<dyn std::error::Error>> {
    let bind_addr = match rendezvous_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = [0; 1024];

    // 1. Register
    println!(
        "Registering at Rendezvous Server {} as '{}'...",
        rendezvous_addr, name
    );
    let reg_msg = format!("REG {} {} {}", name, cap, loc);
    let mut reg_ok = false;
    for _ in 0..5 {
        // Retry 5 times
        socket.send_to(reg_msg.as_bytes(), rendezvous_addr)?;
        match socket.recv_from(&mut buf) {
            Ok((len, src)) if src == rendezvous_addr => {
                let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                if reply == "REG_OK" {
                    reg_ok = true;
                    break;
                }
            }
            _ => {}
        }
    }

    if !reg_ok {
        return Err("Failed to register at Rendezvous Server".into());
    }
    println!("Registration successful.");

    // 2. Wait for PUNCH from server
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    println!("Waiting for peer connection (sending keep-alives every 10s)...");
    let peer_addr = loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                if src == rendezvous_addr {
                    let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                    if reply.starts_with("PUNCH ") {
                        let parts: Vec<&str> = reply.split_whitespace().collect();
                        if parts.len() >= 3 && parts[2] == "passive" {
                            let addr: SocketAddr = parts[1].parse()?;
                            break addr;
                        }
                    }
                }
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Timeout, send keep-alive
                debug!("Sending keep-alive to Rendezvous Server...");
                socket.send_to(reg_msg.as_bytes(), rendezvous_addr).ok();
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    };

    // 3. Hole Punching Phase
    info!(
        "Received connection request from {}. Starting hole punching...",
        peer_addr
    );
    let _final_peer_addr = perform_hole_punching(&socket, peer_addr)?;

    // Reset timeout
    socket.set_read_timeout(None)?;
    Ok(socket)
}

pub fn run_client_p2p_handshake(
    rendezvous_addr: SocketAddr,
) -> Result<(UdpSocket, SocketAddr), Box<dyn std::error::Error>> {
    let bind_addr = match rendezvous_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = [0; 1024];

    // 1. Query servers
    println!("Querying Rendezvous Server at {}...", rendezvous_addr);
    let mut list_received = false;
    let mut servers = Vec::new();
    for _ in 0..3 {
        // Retry 3 times
        socket.send_to(b"QRY", rendezvous_addr)?;
        match socket.recv_from(&mut buf) {
            Ok((len, src)) if src == rendezvous_addr => {
                let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                if let Some(list_str) = reply.strip_prefix("LIST ") {
                    if !list_str.is_empty() {
                        for s in list_str.split(',') {
                            let parts: Vec<&str> = s.split(':').collect();
                            if parts.len() == 3 {
                                servers.push((
                                    parts[0].to_string(),
                                    parts[1].to_string(),
                                    parts[2].to_string(),
                                ));
                            }
                        }
                    }
                    list_received = true;
                    break;
                }
            }
            _ => {}
        }
    }

    if !list_received {
        return Err("Failed to get server list from Rendezvous Server".into());
    }

    if servers.is_empty() {
        return Err("No registered quic-to-tcp servers available".into());
    }

    // 2. Show list and ask user
    println!("\nAvailable Servers:");
    for (i, (name, cap, loc)) in servers.iter().enumerate() {
        println!("{}: {} (Capacity: {}, Location: {})", i + 1, name, cap, loc);
    }

    let mut selection = String::new();
    let selected_idx = loop {
        print!("\nSelect a server (1-{}): ", servers.len());
        io::stdout().flush()?;
        selection.clear();
        io::stdin().read_line(&mut selection)?;
        if let Some(idx) = selection
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|&idx| idx > 0 && idx <= servers.len())
        {
            break idx - 1;
        }
        println!("Invalid selection, try again.");
    };

    let target_name = &servers[selected_idx].0;

    // 3. Send CONN and wait for PUNCH
    println!("Requesting connection to {}...", target_name);
    socket.set_read_timeout(Some(Duration::from_secs(5)))?; // longer timeout for punch
    let mut peer_addr = None;
    for _ in 0..3 {
        let conn_msg = format!("CONN {}", target_name);
        socket.send_to(conn_msg.as_bytes(), rendezvous_addr)?;
        match socket.recv_from(&mut buf) {
            Ok((len, src)) if src == rendezvous_addr => {
                let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                if reply.starts_with("PUNCH ") {
                    let parts: Vec<&str> = reply.split_whitespace().collect();
                    if parts.len() >= 3 && parts[2] == "active" {
                        let addr: SocketAddr = parts[1].parse()?;
                        peer_addr = Some(addr);
                        break;
                    }
                } else if reply.starts_with("ERR") {
                    return Err(format!("Server error: {}", reply).into());
                }
            }
            _ => {}
        }
    }

    let peer_addr = match peer_addr {
        Some(addr) => addr,
        None => return Err("Failed to get peer address from P2P server".into()),
    };

    // 4. Hole Punching Phase
    println!("Starting UDP hole punching to {}...", peer_addr);
    let final_peer_addr = perform_hole_punching(&socket, peer_addr)?;

    // Reset timeout
    socket.set_read_timeout(None)?;
    Ok((socket, final_peer_addr))
}
