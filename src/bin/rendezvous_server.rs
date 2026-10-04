use quic_tcp::auth::{ReplayFilter, compute_auth, next_seq};
use quic_tcp::normalize_socket_addr;
use quic_tcp::protocol::{ClientConn, ClientReset, PunchSignal, RegOk, ServerReg, ServerStatusMsg};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct ServerRecord {
    public_addr: SocketAddr,
    tunnel_id: String,
    tcp_port: u16,
    status: String,
    tunnel_code: String,
    connected_client: Option<SocketAddr>,
    last_seen: Instant,
}

struct RendezvousServer {
    socket: UdpSocket,
    servers: HashMap<String, ServerRecord>,
    replay_filter: ReplayFilter,
    peer_timeout: Duration,
    stale_cleanup_timeout: Duration,
}

impl RendezvousServer {
    fn new(socket: UdpSocket, peer_timeout: Duration, stale_cleanup_timeout: Duration) -> Self {
        Self {
            socket,
            servers: HashMap::new(),
            replay_filter: ReplayFilter::new(),
            peer_timeout,
            stale_cleanup_timeout,
        }
    }

    fn check_timeouts(&mut self) {
        let mut stale_tunnels = Vec::new();

        for (tunnel_id, record) in self.servers.iter_mut() {
            let elapsed = record.last_seen.elapsed();

            // If a server has been silent for longer than peer_timeout and is not already OFFLINE
            if elapsed >= self.peer_timeout && record.status != "OFFLINE" {
                if let Some(client_addr) = record.connected_client.take() {
                    println!(
                        "[TIMEOUT] Tunnel '{}' ({}) timed out after {:.1}s of silence. Status {} -> OFFLINE | Disconnected Client: {}",
                        tunnel_id,
                        record.public_addr,
                        elapsed.as_secs_f32(),
                        record.status,
                        client_addr
                    );
                } else {
                    println!(
                        "[TIMEOUT] Tunnel '{}' ({}) timed out after {:.1}s of silence. Status {} -> OFFLINE",
                        tunnel_id,
                        record.public_addr,
                        elapsed.as_secs_f32(),
                        record.status
                    );
                }
                record.status = "OFFLINE".to_string();
            }

            // If a server has been OFFLINE for longer than stale_cleanup_timeout, prune it
            if record.status == "OFFLINE" && elapsed >= self.stale_cleanup_timeout {
                stale_tunnels.push(tunnel_id.clone());
            }
        }

        for tunnel_id in stale_tunnels {
            if let Some(record) = self.servers.remove(&tunnel_id) {
                println!(
                    "[CLEANUP] Pruned stale tunnel '{}' ({}) after {:.1}s of total inactivity.",
                    tunnel_id,
                    record.public_addr,
                    record.last_seen.elapsed().as_secs_f32()
                );
            }
        }
    }

    fn print_status_report(&self) {
        println!(
            "--- [PERIODIC STATUS REPORT] Active Tunnels ({}) ---",
            self.servers.len()
        );
        if self.servers.is_empty() {
            println!("  No active tunnels.");
        } else {
            for (tunnel_id, record) in &self.servers {
                let client_str = match &record.connected_client {
                    Some(client_addr) => format!("Connected Client: {}", client_addr),
                    None => "Connected Client: None".to_string(),
                };
                let last_seen_str = format!("{:.1}s ago", record.last_seen.elapsed().as_secs_f32());
                println!(
                    "  Tunnel ID '{}' ({}, Port: {}) -> Status: {:<7} | Last Seen: {:<9} | {}",
                    tunnel_id,
                    record.public_addr,
                    record.tcp_port,
                    record.status,
                    last_seen_str,
                    client_str
                );
            }
        }
        println!("----------------------------------------------------");
    }

    fn handle_reg(&mut self, text: &str, src: SocketAddr) {
        let Some(reg) = ServerReg::parse(text) else {
            self.socket.send_to(b"ERR Invalid REG format", src).ok();
            return;
        };

        if !self.replay_filter.check_and_add(reg.seq) {
            eprintln!(
                "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                reg.seq, src
            );
            self.socket
                .send_to(
                    b"ERR Replay attack detected: duplicate or stale sequence number",
                    src,
                )
                .ok();
            return;
        }

        if !reg.verify(&reg.tunnel_code) {
            eprintln!(
                "[AUTH FAILURE] Invalid HMAC from {} for REG command (rejected registration)",
                src
            );
            self.socket
                .send_to(
                    b"ERR Server registration rejected: invalid HMAC signature",
                    src,
                )
                .ok();
            return;
        }

        // If tunnel already exists, ensure passcode matches
        if let Some(existing) = self.servers.get(&reg.tunnel_id) {
            if existing.tunnel_code != reg.tunnel_code {
                eprintln!(
                    "[AUTH FAILURE] Tunnel ID conflict with different secret from {}",
                    src
                );
                self.socket
                    .send_to(b"ERR Server registration rejected: tunnel ID already registered with different secret", src)
                    .ok();
                return;
            }
        }

        let was_offline = self
            .servers
            .get(&reg.tunnel_id)
            .map(|r| r.status == "OFFLINE")
            .unwrap_or(false);
        let prev_client = self
            .servers
            .get(&reg.tunnel_id)
            .and_then(|r| r.connected_client);
        let connected_client = if reg.status == "IDLE" {
            None
        } else {
            prev_client
        };
        let is_update = self.servers.contains_key(&reg.tunnel_id);

        self.servers.insert(
            reg.tunnel_id.clone(),
            ServerRecord {
                public_addr: src,
                tunnel_id: reg.tunnel_id.clone(),
                tcp_port: reg.tcp_port,
                status: reg.status.clone(),
                tunnel_code: reg.tunnel_code.clone(),
                connected_client,
                last_seen: Instant::now(),
            },
        );

        if was_offline {
            println!(
                "[RECONNECTED] Server for tunnel '{}' came back ONLINE: endpoint={} tcp_port={} status={}",
                reg.tunnel_id, src, reg.tcp_port, reg.status
            );
        } else if is_update {
            println!(
                "[Auth OK] Updated registered tunnel: id='{}' endpoint={} tcp_port={} status={}",
                reg.tunnel_id, src, reg.tcp_port, reg.status
            );
        } else {
            println!(
                "[Auth OK] Registered new tunnel: id='{}' endpoint={} tcp_port={} status={}",
                reg.tunnel_id, src, reg.tcp_port, reg.status
            );
        }

        let reg_ok = RegOk::new_signed(&reg.tunnel_code);
        self.socket.send_to(reg_ok.as_bytes(), src).ok();
    }

    fn handle_status(&mut self, text: &str, src: SocketAddr) {
        let Some(msg) = ServerStatusMsg::parse(text) else {
            return;
        };

        if !self.replay_filter.check_and_add(msg.seq) {
            eprintln!(
                "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                msg.seq, src
            );
            return;
        }

        let Some(record) = self.servers.get_mut(&msg.tunnel_id) else {
            return;
        };

        if !msg.verify(&record.tunnel_code) {
            eprintln!(
                "[AUTH FAILURE] Invalid HMAC from {} for STATUS command",
                src
            );
            self.socket
                .send_to(b"ERR Server status rejected: invalid passcode HMAC", src)
                .ok();
            return;
        }

        record.status = msg.status.clone();
        record.public_addr = src;
        record.last_seen = Instant::now();
        if msg.status == "IDLE" {
            record.connected_client = None;
        }
        println!(
            "[Auth OK] Tunnel '{}' status updated to: {}",
            msg.tunnel_id, msg.status
        );

        let resp_seq = next_seq();
        let resp_payload = format!("STATUS_OK:{}", resp_seq);
        let resp_hmac = compute_auth(&record.tunnel_code, &resp_payload);
        let reply = format!("STATUS_OK {} {}", resp_seq, resp_hmac);
        self.socket.send_to(reply.as_bytes(), src).ok();
    }

    fn handle_conn(&mut self, text: &str, src: SocketAddr) {
        let Some(conn) = ClientConn::parse(text) else {
            self.socket.send_to(b"ERR Invalid CONN format", src).ok();
            return;
        };

        if !self.replay_filter.check_and_add(conn.seq) {
            eprintln!(
                "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                conn.seq, src
            );
            self.socket
                .send_to(
                    b"ERR Replay attack detected: duplicate or stale sequence number",
                    src,
                )
                .ok();
            return;
        }

        let target_record = match self.servers.get_mut(&conn.tunnel_id) {
            Some(rec) => rec,
            None => {
                eprintln!(
                    "[CONN REJECTED] No tunnel registered matching ID {}",
                    conn.tunnel_id
                );
                let err_msg = format!(
                    "ERR No server registered matching tunnel ID {}",
                    conn.tunnel_id
                );
                self.socket.send_to(err_msg.as_bytes(), src).ok();
                return;
            }
        };

        if !conn.verify(&target_record.tunnel_code) {
            eprintln!(
                "[AUTH FAILURE] Client {} provided invalid passcode for tunnel {}",
                src, conn.tunnel_id
            );
            let err_msg = format!(
                "ERR Authentication failed: incorrect passcode for tunnel {}",
                conn.tunnel_id
            );
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        if target_record.status == "OFFLINE" {
            println!(
                "[CONN REJECTED] Client {} requested tunnel {} but server is OFFLINE (unresponsive for {:.1}s)",
                src,
                conn.tunnel_id,
                target_record.last_seen.elapsed().as_secs_f32()
            );
            let err_msg = format!(
                "ERR Server for tunnel {} is currently OFFLINE and unresponsive",
                conn.tunnel_id
            );
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        if target_record.status == "BUSY" {
            println!(
                "[REJECTED] Client {} requested tunnel {} but it is BUSY",
                src, conn.tunnel_id
            );
            let err_msg = format!(
                "ERR Tunnel {} is currently BUSY and already connected to another client",
                conn.tunnel_id
            );
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        let target_addr = target_record.public_addr;
        let tunnel_id = target_record.tunnel_id.clone();
        let srv_code = target_record.tunnel_code.clone();

        // Check that both peers use the same IP family (IPv4 vs IPv6)
        if src.is_ipv4() != target_addr.is_ipv4() {
            let client_ip_type = if src.is_ipv4() { "IPv4" } else { "IPv6" };
            let server_ip_type = if target_addr.is_ipv4() {
                "IPv4"
            } else {
                "IPv6"
            };
            eprintln!(
                "[IP MISMATCH ERROR] Tunnel ID '{}': Client ({}: {}) and Server ({}: {}) use different IP versions. Rejecting connection.",
                conn.tunnel_id, client_ip_type, src, server_ip_type, target_addr
            );
            println!(
                "[IP MISMATCH ERROR] Tunnel ID '{}': Client ({}: {}) and Server ({}: {}) use different IP versions. Rejecting connection.",
                conn.tunnel_id, client_ip_type, src, server_ip_type, target_addr
            );
            let err_msg = format!(
                "ERR IP address family mismatch: client is using {} ({}) but server is registered with {} ({})",
                client_ip_type, src, server_ip_type, target_addr
            );
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        println!(
            "[Auth OK] Connecting client {} to server '{}' ({}) - Status -> BUSY",
            src, tunnel_id, target_addr
        );

        target_record.status = "BUSY".to_string();
        target_record.connected_client = Some(src);

        // Control PUNCH to target server (passive)
        let punch_to_srv = PunchSignal::new_passive_signed(src, &srv_code);
        self.socket
            .send_to(punch_to_srv.as_bytes(), target_addr)
            .ok();

        // Control PUNCH to client (active)
        let punch_to_cli = PunchSignal::new_active_signed(target_addr, &srv_code);
        self.socket.send_to(punch_to_cli.as_bytes(), src).ok();
    }

    fn handle_reset(&mut self, text: &str, src: SocketAddr) {
        let Some(reset) = ClientReset::parse(text) else {
            self.socket.send_to(b"ERR Invalid RESET format", src).ok();
            return;
        };

        if !self.replay_filter.check_and_add(reset.seq) {
            eprintln!(
                "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                reset.seq, src
            );
            self.socket
                .send_to(
                    b"ERR Replay attack detected: duplicate or stale sequence number",
                    src,
                )
                .ok();
            return;
        }

        let target_record = match self.servers.get_mut(&reset.tunnel_id) {
            Some(rec) => rec,
            None => {
                eprintln!(
                    "[RESET REJECTED] No tunnel registered matching ID {}",
                    reset.tunnel_id
                );
                let err_msg = format!(
                    "ERR No server registered matching tunnel ID {}",
                    reset.tunnel_id
                );
                self.socket.send_to(err_msg.as_bytes(), src).ok();
                return;
            }
        };

        if !reset.verify(&target_record.tunnel_code) {
            eprintln!(
                "[AUTH FAILURE] Client {} provided invalid passcode for RESET on tunnel {}",
                src, reset.tunnel_id
            );
            let err_msg = format!(
                "ERR Authentication failed: incorrect passcode for tunnel {}",
                reset.tunnel_id
            );
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        if target_record.status == "OFFLINE" {
            println!(
                "[RESET REJECTED] Client {} requested RESET for tunnel {} but server is OFFLINE",
                src, reset.tunnel_id
            );
            let err_msg = format!(
                "ERR Server for tunnel {} is currently OFFLINE and cannot be reset",
                reset.tunnel_id
            );
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        let target_addr = target_record.public_addr;
        let tunnel_id = target_record.tunnel_id.clone();
        let srv_code = target_record.tunnel_code.clone();

        // Check that both peers use the same IP family (IPv4 vs IPv6)
        if src.is_ipv4() != target_addr.is_ipv4() {
            let client_ip_type = if src.is_ipv4() { "IPv4" } else { "IPv6" };
            let server_ip_type = if target_addr.is_ipv4() {
                "IPv4"
            } else {
                "IPv6"
            };
            eprintln!(
                "[IP MISMATCH ERROR] Tunnel ID '{}': Client ({}: {}) and Server ({}: {}) use different IP versions during RESET. Rejecting.",
                reset.tunnel_id, client_ip_type, src, server_ip_type, target_addr
            );
            println!(
                "[IP MISMATCH ERROR] Tunnel ID '{}': Client ({}: {}) and Server ({}: {}) use different IP versions during RESET. Rejecting.",
                reset.tunnel_id, client_ip_type, src, server_ip_type, target_addr
            );
            let err_msg = format!(
                "ERR IP address family mismatch: client is using {} ({}) but server is registered with {} ({})",
                client_ip_type, src, server_ip_type, target_addr
            );
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        println!(
            "[RESET ACCEPTED] Client {} reported dead socket. Signaling server '{}' ({}) to reset and restart hole punching...",
            src, tunnel_id, target_addr
        );

        target_record.status = "BUSY".to_string();
        target_record.connected_client = Some(src);

        // Control PUNCH to target server (passive)
        let punch_to_srv = PunchSignal::new_passive_signed(src, &srv_code);
        self.socket
            .send_to(punch_to_srv.as_bytes(), target_addr)
            .ok();

        // Control PUNCH to client (active)
        let punch_to_cli = PunchSignal::new_active_signed(target_addr, &srv_code);
        self.socket.send_to(punch_to_cli.as_bytes(), src).ok();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let bind_arg = if args.len() > 1 { &args[1] } else { "5050" };

    let bind_addr: SocketAddr = if let Ok(addr) = bind_arg.parse::<SocketAddr>() {
        addr
    } else if let Ok(port) = bind_arg.parse::<u16>() {
        format!("0.0.0.0:{}", port).parse().unwrap()
    } else {
        use std::net::ToSocketAddrs;
        bind_arg
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| format!("Failed to resolve bind address: {}", bind_arg))?
    };

    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
    println!(
        "Rendezvous Server listening on {} (Unified Secret Auth & Replay Filter ACTIVE)",
        bind_addr
    );

    let peer_timeout_secs: u64 = std::env::var("RENDEZVOUS_PEER_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let cleanup_timeout_secs: u64 = std::env::var("RENDEZVOUS_CLEANUP_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120);

    let peer_timeout = Duration::from_secs(peer_timeout_secs);
    let stale_cleanup_timeout = Duration::from_secs(cleanup_timeout_secs);

    let mut server = RendezvousServer::new(socket, peer_timeout, stale_cleanup_timeout);
    let mut buf = [0; 2048];
    let mut last_status_dump = Instant::now();

    loop {
        server.check_timeouts();

        if last_status_dump.elapsed() >= std::time::Duration::from_secs(10) {
            last_status_dump = Instant::now();
            server.print_status_report();
        }

        match server.socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let src = normalize_socket_addr(src);
                let text = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                if text.starts_with("REG ") {
                    server.handle_reg(text, src);
                } else if text.starts_with("STATUS ") {
                    server.handle_status(text, src);
                } else if text.starts_with("CONN ") {
                    server.handle_conn(text, src);
                } else if text.starts_with("RESET ") {
                    server.handle_reset(text, src);
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Timeout for periodic status check & timeout verification
            }
            Err(e) => {
                eprintln!("Socket recv error: {}", e);
            }
        }
    }
}
