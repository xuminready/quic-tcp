use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let port = if args.len() > 1 { &args[1] } else { "5000" };
    let bind_addr = format!("0.0.0.0:{}", port);

    let socket = UdpSocket::bind(&bind_addr)?;
    println!("Rendezvous Server listening on {}", bind_addr);

    // Maps server name -> (Public SocketAddr, Capacity, Location)
    let mut servers: HashMap<String, (SocketAddr, String, String)> = HashMap::new();
    let mut buf = [0; 1024];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let msg = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                let parts: Vec<&str> = msg.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                match parts[0] {
                    "REG" => {
                        if parts.len() >= 4 {
                            let name = parts[1].to_string();
                            let cap = parts[2].to_string();
                            let loc = parts[3].to_string();
                            servers.insert(name.clone(), (src, cap.clone(), loc.clone()));
                            println!(
                                "Registered server: '{}' at {} (Cap: {}, Loc: {})",
                                name, src, cap, loc
                            );
                            socket.send_to(b"REG_OK", src).ok();
                        } else {
                            socket.send_to(b"ERR Invalid REG format. Expected: REG <name> <capacity> <location>", src).ok();
                        }
                    }
                    "QRY" => {
                        let mut list = Vec::new();
                        for (name, (_, cap, loc)) in &servers {
                            list.push(format!("{}:{}:{}", name, cap, loc));
                        }
                        let reply = format!("LIST {}", list.join(","));
                        socket.send_to(reply.as_bytes(), src).ok();
                    }
                    "CONN" => {
                        if parts.len() >= 2 {
                            let target_name = parts[1];
                            if let Some(&(target_addr, _, _)) = servers.get(target_name) {
                                println!(
                                    "Connecting client {} to server '{}' ({})",
                                    src, target_name, target_addr
                                );

                                // Tell the target server (A) to punch to the client (B)
                                let msg_to_a = format!("PUNCH {} passive", src);
                                socket.send_to(msg_to_a.as_bytes(), target_addr).ok();

                                // Tell the client (B) to punch to the target server (A)
                                let msg_to_b = format!("PUNCH {} active", target_addr);
                                socket.send_to(msg_to_b.as_bytes(), src).ok();
                            } else {
                                println!(
                                    "Connection request from {} failed: server '{}' not found",
                                    src, target_name
                                );
                                socket.send_to(b"ERR Server not found", src).ok();
                            }
                        } else {
                            socket
                                .send_to(
                                    b"ERR Invalid CONN format. Expected: CONN <server_name>",
                                    src,
                                )
                                .ok();
                        }
                    }
                    _ => {
                        debug_assert!(false, "Unknown command: {}", parts[0]);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}
