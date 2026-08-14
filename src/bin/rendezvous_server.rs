use quic_tcp::auth::{compute_auth, next_seq, ReplayFilter};
use quic_tcp::protocol::{ClientConn, ClientReset, PunchSignal, RegOk, ServerReg, ServerStatusMsg};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

#[derive(Debug, Clone)]
struct ServerRecord {
    public_addr: SocketAddr,
    tcp_port: u16,
    status: String,
    server_passcode: String,
    connected_client: Option<SocketAddr>,
}

struct RendezvousServer {
    socket: UdpSocket,
    server_reg_passcode: String,
    servers: HashMap<String, ServerRecord>,
    replay_filter: ReplayFilter,
}

impl RendezvousServer {
    fn new(socket: UdpSocket, server_reg_passcode: String) -> Self {
        Self {
            socket,
            server_reg_passcode,
            servers: HashMap::new(),
            replay_filter: ReplayFilter::new(),
        }
    }

    fn print_status_report(&self) {
        println!(
            "--- [PERIODIC STATUS REPORT] Registered Servers ({}) ---",
            self.servers.len()
        );
        if self.servers.is_empty() {
            println!("  No registered servers.");
        } else {
            for (name, record) in &self.servers {
                match &record.connected_client {
                    Some(client_addr) => println!(
                        "  Server '{}' ({}, TCP port: {}) -> Status: {} | Connected Client: {}",
                        name, record.public_addr, record.tcp_port, record.status, client_addr
                    ),
                    None => println!(
                        "  Server '{}' ({}, TCP port: {}) -> Status: {} | Connected Client: None",
                        name, record.public_addr, record.tcp_port, record.status
                    ),
                }
            }
        }
        println!("-------------------------------------------------------");
    }

    fn handle_reg(&mut self, text: &str, src: SocketAddr) {
        let Some(reg) = ServerReg::parse(text) else {
            self.socket
                .send_to(b"ERR Invalid REG format", src)
                .ok();
            return;
        };

        if !self.replay_filter.check_and_add(reg.seq) {
            eprintln!("[REPLAY ATTACK] Duplicate/stale sequence number {} from {}", reg.seq, src);
            self.socket
                .send_to(b"ERR Replay attack detected: duplicate or stale sequence number", src)
                .ok();
            return;
        }

        if !reg.verify(&self.server_reg_passcode) {
            eprintln!("[AUTH FAILURE] Invalid HMAC from {} for REG command (rejected registration)", src);
            self.socket
                .send_to(b"ERR Server registration rejected: invalid rendezvous passcode", src)
                .ok();
            return;
        }

        let prev_client = self.servers.get(&reg.name).and_then(|r| r.connected_client);
        let connected_client = if reg.status == "IDLE" { None } else { prev_client };
        let is_update = self.servers.contains_key(&reg.name);

        self.servers.insert(
            reg.name.clone(),
            ServerRecord {
                public_addr: src,
                tcp_port: reg.tcp_port,
                status: reg.status.clone(),
                server_passcode: reg.server_passcode,
                connected_client,
            },
        );

        if is_update {
            println!(
                "[Auth OK] Updated registered server: '{}' endpoint={} tcp_port={} status={}",
                reg.name, src, reg.tcp_port, reg.status
            );
        } else {
            println!(
                "[Auth OK] Registered new server: '{}' endpoint={} tcp_port={} status={}",
                reg.name, src, reg.tcp_port, reg.status
            );
        }

        let reg_ok = RegOk::new_signed(&self.server_reg_passcode);
        self.socket.send_to(reg_ok.as_bytes(), src).ok();
    }

    fn handle_status(&mut self, text: &str, src: SocketAddr) {
        let Some(msg) = ServerStatusMsg::parse(text) else { return; };

        if !self.replay_filter.check_and_add(msg.seq) {
            eprintln!("[REPLAY ATTACK] Duplicate/stale sequence number {} from {}", msg.seq, src);
            return;
        }

        if !msg.verify(&self.server_reg_passcode) {
            eprintln!("[AUTH FAILURE] Invalid HMAC from {} for STATUS command", src);
            self.socket
                .send_to(b"ERR Server status rejected: invalid rendezvous passcode", src)
                .ok();
            return;
        }

        if let Some(record) = self.servers.get_mut(&msg.name) {
            record.status = msg.status.clone();
            record.public_addr = src;
            if msg.status == "IDLE" {
                record.connected_client = None;
            }
            println!("[Auth OK] Server '{}' status updated to: {}", msg.name, msg.status);
        }

        let resp_seq = next_seq();
        let resp_payload = format!("STATUS_OK:{}", resp_seq);
        let resp_hmac = compute_auth(&self.server_reg_passcode, &resp_payload);
        let reply = format!("STATUS_OK {} {}", resp_seq, resp_hmac);
        self.socket.send_to(reply.as_bytes(), src).ok();
    }

    fn handle_conn(&mut self, text: &str, src: SocketAddr) {
        let Some(conn) = ClientConn::parse(text) else {
            self.socket.send_to(b"ERR Invalid CONN format", src).ok();
            return;
        };

        if !self.replay_filter.check_and_add(conn.seq) {
            eprintln!("[REPLAY ATTACK] Duplicate/stale sequence number {} from {}", conn.seq, src);
            self.socket
                .send_to(b"ERR Replay attack detected: duplicate or stale sequence number", src)
                .ok();
            return;
        }

        let server_entry = self.servers.iter_mut().find(|(_, rec)| rec.tcp_port == conn.target_tcp_port);
        let (target_name, target_record) = match server_entry {
            Some((name, rec)) => (name.clone(), rec),
            None => {
                eprintln!("[CONN REJECTED] No server registered matching target TCP port {}", conn.target_tcp_port);
                let err_msg = format!("ERR No server registered matching target TCP port {}", conn.target_tcp_port);
                self.socket.send_to(err_msg.as_bytes(), src).ok();
                return;
            }
        };

        if !conn.verify(&target_record.server_passcode) {
            eprintln!("[AUTH FAILURE] Client {} provided invalid passcode for TCP port {}", src, conn.target_tcp_port);
            let err_msg = format!("ERR Authentication failed: incorrect server passcode for target TCP port {}", conn.target_tcp_port);
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        if target_record.status == "BUSY" {
            println!("[REJECTED] Client {} requested server for TCP port {} but it is BUSY", src, conn.target_tcp_port);
            let err_msg = format!(
                "ERR Server for target TCP port {} is currently BUSY and already connected to another client",
                conn.target_tcp_port
            );
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        let target_addr = target_record.public_addr;
        let srv_passcode = target_record.server_passcode.clone();
        println!(
            "[Auth OK] Connecting client {} to server '{}' ({}) for TCP Port {} - Status -> BUSY",
            src, target_name, target_addr, conn.target_tcp_port
        );

        target_record.status = "BUSY".to_string();
        target_record.connected_client = Some(src);

        // Control PUNCH to target server (passive)
        let punch_to_srv = PunchSignal::new_passive_signed(src, &srv_passcode);
        self.socket.send_to(punch_to_srv.as_bytes(), target_addr).ok();

        // Control PUNCH to client (active)
        let punch_to_cli = PunchSignal::new_active_signed(target_addr, &target_name, &srv_passcode);
        self.socket.send_to(punch_to_cli.as_bytes(), src).ok();
    }

    fn handle_reset(&mut self, text: &str, src: SocketAddr) {
        let Some(reset) = ClientReset::parse(text) else {
            self.socket.send_to(b"ERR Invalid RESET format", src).ok();
            return;
        };

        if !self.replay_filter.check_and_add(reset.seq) {
            eprintln!("[REPLAY ATTACK] Duplicate/stale sequence number {} from {}", reset.seq, src);
            self.socket
                .send_to(b"ERR Replay attack detected: duplicate or stale sequence number", src)
                .ok();
            return;
        }

        let server_entry = self.servers.iter_mut().find(|(_, rec)| rec.tcp_port == reset.target_tcp_port);
        let (target_name, target_record) = match server_entry {
            Some((name, rec)) => (name.clone(), rec),
            None => {
                eprintln!("[RESET REJECTED] No server registered matching target TCP port {}", reset.target_tcp_port);
                let err_msg = format!("ERR No server registered matching target TCP port {}", reset.target_tcp_port);
                self.socket.send_to(err_msg.as_bytes(), src).ok();
                return;
            }
        };

        if !reset.verify(&target_record.server_passcode) {
            eprintln!("[AUTH FAILURE] Client {} provided invalid passcode for RESET on TCP port {}", src, reset.target_tcp_port);
            let err_msg = format!("ERR Authentication failed: incorrect server passcode for target TCP port {}", reset.target_tcp_port);
            self.socket.send_to(err_msg.as_bytes(), src).ok();
            return;
        }

        let target_addr = target_record.public_addr;
        let srv_passcode = target_record.server_passcode.clone();
        println!(
            "[RESET ACCEPTED] Client {} reported dead socket. Signaling server '{}' ({}) to reset and restart hole punching...",
            src, target_name, target_addr
        );

        target_record.status = "BUSY".to_string();
        target_record.connected_client = Some(src);

        // Control PUNCH to target server (passive)
        let punch_to_srv = PunchSignal::new_passive_signed(src, &srv_passcode);
        self.socket.send_to(punch_to_srv.as_bytes(), target_addr).ok();

        // Control PUNCH to client (active)
        let punch_to_cli = PunchSignal::new_active_signed(target_addr, &target_name, &srv_passcode);
        self.socket.send_to(punch_to_cli.as_bytes(), src).ok();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let port = if args.len() > 1 { &args[1] } else { "5000" };
    let server_reg_passcode = if args.len() > 2 {
        args[2].clone()
    } else {
        println!("INFO: No registration passcode provided on CLI. Using default passcode: 'secret123'");
        "secret123".to_string()
    };

    let bind_addr = format!("0.0.0.0:{}", port);
    let socket = UdpSocket::bind(&bind_addr)?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
    println!(
        "Rendezvous Server listening on {} (Server Registration Auth & Replay Filter ACTIVE)",
        bind_addr
    );

    let mut server = RendezvousServer::new(socket, server_reg_passcode);
    let mut buf = [0; 2048];
    let mut last_status_dump = Instant::now();

    loop {
        if last_status_dump.elapsed() >= std::time::Duration::from_secs(10) {
            last_status_dump = Instant::now();
            server.print_status_report();
        }

        match server.socket.recv_from(&mut buf) {
            Ok((len, src)) => {
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
                // Timeout for periodic status check
            }
            Err(e) => {
                eprintln!("Socket recv error: {}", e);
            }
        }
    }
}
