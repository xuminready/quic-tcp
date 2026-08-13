use quic_tcp::p2p::{compute_auth, next_seq, verify_auth, ReplayFilter};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};

#[derive(Debug, Clone)]
struct ServerRecord {
    public_addr: SocketAddr,
    tcp_port: u16,
    status: String,
    server_passcode: String,
    connected_client: Option<SocketAddr>,
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

    let mut servers: HashMap<String, ServerRecord> = HashMap::new();
    let mut replay_filter = ReplayFilter::new();
    let mut buf = [0; 2048];
    let mut last_status_dump = std::time::Instant::now();

    loop {
        if last_status_dump.elapsed() >= std::time::Duration::from_secs(10) {
            last_status_dump = std::time::Instant::now();
            println!(
                "--- [PERIODIC STATUS REPORT] Registered Servers ({}) ---",
                servers.len()
            );
            if servers.is_empty() {
                println!("  No registered servers.");
            } else {
                for (name, record) in &servers {
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

        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let msg = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                let parts: Vec<&str> = msg.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                match parts[0] {
                    "REG" => {
                        // REG <name> <tcp_port> <status> <server_passcode> <seq> <hmac>
                        if parts.len() >= 7 {
                            let name = parts[1].to_string();
                            let tcp_port = parts[2].parse::<u16>().unwrap_or(0);
                            let status = parts[3].to_string();
                            let srv_passcode = parts[4].to_string();
                            let seq = parts[5].parse::<u64>().unwrap_or(0);
                            let hmac = parts[6];

                            if !replay_filter.check_and_add(seq) {
                                eprintln!(
                                    "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                                    seq, src
                                );
                                socket
                                    .send_to(b"ERR Replay attack detected: duplicate or stale sequence number", src)
                                    .ok();
                                continue;
                            }

                            let payload = format!("REG:{}:{}:{}:{}:{}", name, tcp_port, status, srv_passcode, seq);
                            if !verify_auth(&server_reg_passcode, &payload, hmac) {
                                eprintln!(
                                    "[AUTH FAILURE] Invalid HMAC from {} for REG command (rejected registration)",
                                    src
                                );
                                socket
                                    .send_to(b"ERR Server registration rejected: invalid rendezvous passcode", src)
                                    .ok();
                                continue;
                            }

                            let prev_client = servers.get(&name).and_then(|r| r.connected_client);
                            let connected_client = if status == "IDLE" {
                                None
                            } else {
                                prev_client
                            };

                            let is_update = servers.contains_key(&name);
                            servers.insert(
                                name.clone(),
                                ServerRecord {
                                    public_addr: src,
                                    tcp_port,
                                    status: status.clone(),
                                    server_passcode: srv_passcode,
                                    connected_client,
                                },
                            );

                            if is_update {
                                println!(
                                    "[Auth OK] Updated registered server: '{}' endpoint={} tcp_port={} status={}",
                                    name, src, tcp_port, status
                                );
                            } else {
                                println!(
                                    "[Auth OK] Registered new server: '{}' endpoint={} tcp_port={} status={}",
                                    name, src, tcp_port, status
                                );
                            }

                            let resp_seq = next_seq();
                            let resp_payload = format!("REG_OK:{}", resp_seq);
                            let resp_hmac = compute_auth(&server_reg_passcode, &resp_payload);
                            let reply = format!("REG_OK {} {}", resp_seq, resp_hmac);
                            socket.send_to(reply.as_bytes(), src).ok();
                        } else {
                            socket
                                .send_to(
                                    b"ERR Invalid REG format. Expected: REG <name> <tcp_port> <status> <server_passcode> <seq> <hmac>",
                                    src,
                                )
                                .ok();
                        }
                    }

                    "STATUS" => {
                        // STATUS <name> <status> <seq> <hmac>
                        if parts.len() >= 5 {
                            let name = parts[1].to_string();
                            let status = parts[2].to_string();
                            let seq = parts[3].parse::<u64>().unwrap_or(0);
                            let hmac = parts[4];

                            if !replay_filter.check_and_add(seq) {
                                eprintln!(
                                    "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                                    seq, src
                                );
                                continue;
                            }

                            let payload = format!("STATUS:{}:{}:{}", name, status, seq);
                            if !verify_auth(&server_reg_passcode, &payload, hmac) {
                                eprintln!(
                                    "[AUTH FAILURE] Invalid HMAC from {} for STATUS command",
                                    src
                                );
                                socket
                                    .send_to(b"ERR Server status rejected: invalid rendezvous passcode", src)
                                    .ok();
                                continue;
                            }

                            if let Some(record) = servers.get_mut(&name) {
                                record.status = status.clone();
                                record.public_addr = src;
                                if status == "IDLE" {
                                    record.connected_client = None;
                                }
                                println!(
                                    "[Auth OK] Server '{}' status updated to: {}",
                                    name, status
                                );
                            }

                            let resp_seq = next_seq();
                            let resp_payload = format!("STATUS_OK:{}", resp_seq);
                            let resp_hmac = compute_auth(&server_reg_passcode, &resp_payload);
                            let reply = format!("STATUS_OK {} {}", resp_seq, resp_hmac);
                            socket.send_to(reply.as_bytes(), src).ok();
                        }
                    }

                    "QRY" => {
                        // QRY <target_tcp_port> <seq> <hmac>
                        if parts.len() >= 4 {
                            let target_tcp_port = parts[1].parse::<u16>().unwrap_or(0);
                            let seq = parts[2].parse::<u64>().unwrap_or(0);
                            let hmac = parts[3];

                            if !replay_filter.check_and_add(seq) {
                                eprintln!(
                                    "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                                    seq, src
                                );
                                socket
                                    .send_to(b"ERR Replay attack detected: duplicate or stale sequence number", src)
                                    .ok();
                                continue;
                            }

                            let matching_server = servers.values().find(|rec| rec.tcp_port == target_tcp_port);
                            let server_rec = match matching_server {
                                Some(rec) => rec,
                                None => {
                                    eprintln!("[QRY REJECTED] No server registered matching target TCP port {}", target_tcp_port);
                                    let err_msg = format!("ERR No server registered matching target TCP port {}", target_tcp_port);
                                    socket.send_to(err_msg.as_bytes(), src).ok();
                                    continue;
                                }
                            };

                            let payload = format!("QRY:{}:{}", target_tcp_port, seq);
                            if !verify_auth(&server_rec.server_passcode, &payload, hmac) {
                                eprintln!(
                                    "[AUTH FAILURE] Incorrect server passcode from {} for target TCP port {}",
                                    src, target_tcp_port
                                );
                                let err_msg = format!("ERR Authentication failed: incorrect server passcode for target TCP port {}", target_tcp_port);
                                socket.send_to(err_msg.as_bytes(), src).ok();
                                continue;
                            }

                            let mut list = Vec::new();
                            for (name, rec) in &servers {
                                if rec.tcp_port == target_tcp_port {
                                    list.push(format!("{}:{}:{}", name, rec.tcp_port, rec.status));
                                }
                            }
                            let list_str = list.join(",");
                            println!(
                                "[Auth OK] Client {} queried for TCP Port {} (found {} matching servers)",
                                src, target_tcp_port, list.len()
                            );
                            let encoded_list = if list_str.is_empty() { "NONE" } else { &list_str };
                            let resp_seq = next_seq();
                            let resp_payload = format!("LIST:{}:{}", list_str, resp_seq);
                            let resp_hmac = compute_auth(&server_rec.server_passcode, &resp_payload);
                            let reply = format!("LIST {} {} {}", encoded_list, resp_seq, resp_hmac);
                            socket.send_to(reply.as_bytes(), src).ok();
                        } else {
                            socket
                                .send_to(
                                    b"ERR Invalid QRY format. Expected: QRY <target_tcp_port> <seq> <hmac>",
                                    src,
                                )
                                .ok();
                        }
                    }

                    "CONN" => {
                        // CONN <target_tcp_port> <seq> <hmac>
                        if parts.len() >= 4 {
                            let target_tcp_port = parts[1].parse::<u16>().unwrap_or(0);
                            let seq = parts[2].parse::<u64>().unwrap_or(0);
                            let hmac = parts[3];

                            if !replay_filter.check_and_add(seq) {
                                eprintln!(
                                    "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                                    seq, src
                                );
                                socket
                                    .send_to(b"ERR Replay attack detected: duplicate or stale sequence number", src)
                                    .ok();
                                continue;
                            }

                            let server_entry = servers.iter_mut().find(|(_, rec)| rec.tcp_port == target_tcp_port);
                            let (target_name, target_record) = match server_entry {
                                Some((name, rec)) => (name.clone(), rec),
                                None => {
                                    eprintln!(
                                        "[CONN REJECTED] Client {} requested connection to target TCP port {} but no server is registered for this port",
                                        src, target_tcp_port
                                    );
                                    let err_msg = format!("ERR No server registered matching target TCP port {}", target_tcp_port);
                                    socket.send_to(err_msg.as_bytes(), src).ok();
                                    continue;
                                }
                            };

                            let payload = format!("CONN:{}:{}", target_tcp_port, seq);
                            if !verify_auth(&target_record.server_passcode, &payload, hmac) {
                                eprintln!(
                                    "[AUTH FAILURE] Client {} provided invalid passcode for target TCP port {}",
                                    src, target_tcp_port
                                );
                                let err_msg = format!("ERR Authentication failed: incorrect server passcode for target TCP port {}", target_tcp_port);
                                socket.send_to(err_msg.as_bytes(), src).ok();
                                continue;
                            }

                            if target_record.status == "BUSY" {
                                println!(
                                    "[REJECTED] Client {} requested connection to server for TCP port {} but it is currently BUSY (in use)",
                                    src, target_tcp_port
                                );
                                let err_msg = format!(
                                    "ERR Server for target TCP port {} is currently BUSY and already connected to another client",
                                    target_tcp_port
                                );
                                socket.send_to(err_msg.as_bytes(), src).ok();
                                continue;
                            }

                            let target_addr = target_record.public_addr;
                            let srv_passcode = target_record.server_passcode.clone();
                            println!(
                                "[Auth OK] Connecting client {} to server '{}' ({}) for TCP Port {} - Transitioning server status to BUSY",
                                src, target_name, target_addr, target_tcp_port
                            );

                            // Mark server as BUSY immediately so no other client can connect
                            target_record.status = "BUSY".to_string();
                            target_record.connected_client = Some(src);

                            // Send control PUNCH to target server (A) with authentication using server's passcode
                            let seq_a = next_seq();
                            let payload_a = format!("PUNCH:{}:passive:{}", src, seq_a);
                            let hmac_a = compute_auth(&srv_passcode, &payload_a);
                            let msg_to_a = format!("PUNCH {} passive {} {}", src, seq_a, hmac_a);
                            socket.send_to(msg_to_a.as_bytes(), target_addr).ok();

                            // Send control PUNCH to client (B) with authentication using server's passcode
                            let seq_b = next_seq();
                            let payload_b = format!("PUNCH:{}:active:{}:{}", target_addr, target_name, seq_b);
                            let hmac_b = compute_auth(&srv_passcode, &payload_b);
                            let msg_to_b = format!("PUNCH {} active {} {} {}", target_addr, target_name, seq_b, hmac_b);
                            socket.send_to(msg_to_b.as_bytes(), src).ok();
                        } else {
                            socket
                                .send_to(
                                    b"ERR Invalid CONN format. Expected: CONN <target_tcp_port> <seq> <hmac>",
                                    src,
                                )
                                .ok();
                        }
                    }

                    "RESET" => {
                        // RESET <target_tcp_port> <seq> <hmac>
                        if parts.len() >= 4 {
                            let target_tcp_port = parts[1].parse::<u16>().unwrap_or(0);
                            let seq = parts[2].parse::<u64>().unwrap_or(0);
                            let hmac = parts[3];

                            if !replay_filter.check_and_add(seq) {
                                eprintln!(
                                    "[REPLAY ATTACK] Duplicate/stale sequence number {} from {}",
                                    seq, src
                                );
                                socket
                                    .send_to(b"ERR Replay attack detected: duplicate or stale sequence number", src)
                                    .ok();
                                continue;
                            }

                            let server_entry = servers.iter_mut().find(|(_, rec)| rec.tcp_port == target_tcp_port);
                            let (target_name, target_record) = match server_entry {
                                Some((name, rec)) => (name.clone(), rec),
                                None => {
                                    eprintln!(
                                        "[RESET REJECTED] Reset request for TCP port {} failed: no server registered",
                                        target_tcp_port
                                    );
                                    let err_msg = format!("ERR No server registered matching target TCP port {}", target_tcp_port);
                                    socket.send_to(err_msg.as_bytes(), src).ok();
                                    continue;
                                }
                            };

                            let payload = format!("RESET:{}:{}", target_tcp_port, seq);
                            if !verify_auth(&target_record.server_passcode, &payload, hmac) {
                                eprintln!(
                                    "[AUTH FAILURE] Reset request invalid passcode from {} for target TCP port {}",
                                    src, target_tcp_port
                                );
                                let err_msg = format!("ERR Authentication failed: incorrect server passcode for target TCP port {}", target_tcp_port);
                                socket.send_to(err_msg.as_bytes(), src).ok();
                                continue;
                            }

                            let target_addr = target_record.public_addr;
                            let srv_passcode = target_record.server_passcode.clone();
                            println!(
                                "[Auth OK] Client {} reported dead socket to server '{}' ({}) for TCP Port {}. Resetting server state and initiating hole punching...",
                                src, target_name, target_addr, target_tcp_port
                            );

                            target_record.status = "BUSY".to_string();
                            target_record.connected_client = Some(src);

                            // Signal target server (quic-to-tcp) to reset active session and punch
                            let seq_a = next_seq();
                            let payload_a = format!("PUNCH:{}:passive:{}", src, seq_a);
                            let hmac_a = compute_auth(&srv_passcode, &payload_a);
                            let msg_to_a = format!("PUNCH {} passive {} {}", src, seq_a, hmac_a);
                            socket.send_to(msg_to_a.as_bytes(), target_addr).ok();

                            // Signal client (tcp-to-quic) to punch to server
                            let seq_b = next_seq();
                            let payload_b = format!("PUNCH:{}:active:{}:{}", target_addr, target_name, seq_b);
                            let hmac_b = compute_auth(&srv_passcode, &payload_b);
                            let msg_to_b = format!("PUNCH {} active {} {} {}", target_addr, target_name, seq_b, hmac_b);
                            socket.send_to(msg_to_b.as_bytes(), src).ok();
                        } else {
                            socket
                                .send_to(
                                    b"ERR Invalid RESET format. Expected: RESET <target_tcp_port> <seq> <hmac>",
                                    src,
                                )
                                .ok();
                        }
                    }

                    _ => {
                        eprintln!("Unknown command from {}: {}", src, parts[0]);
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Timeout on read; loop around to check periodic status report
            }
            Err(e) => {
                eprintln!("Error receiving UDP packet: {}", e);
            }
        }
    }
}