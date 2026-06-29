use log::{debug, error, info, warn};
use ring::rand::{SystemRandom, SecureRandom};
use quic_tcp::*; // Import our library
use std::io::Write;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        return Ok(());
    }

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let (mut udp_socket, peer_addr, tcp_local_addr) = if args[1] == "p2p" {
        if args.len() < 4 {
            print_usage(&args[0]);
            return Ok(());
        }
        let rendezvous_addr: std::net::SocketAddr = args[2].parse().map_err(|e| format!("Invalid Rendezvous server address: {}", e))?;
        let tcp_local_addr_str = &args[3];
        let tcp_local_addr: std::net::SocketAddr = tcp_local_addr_str.parse().map_err(|e| format!("Invalid TCP local address: {}", e))?;

        println!("P2P Mode: connecting to Rendezvous Server {}", rendezvous_addr);
        println!("TCP Local Server: {}", tcp_local_addr);

        let (std_socket, peer_addr) = run_client_p2p_handshake(rendezvous_addr)?;
        let udp_socket = mio::net::UdpSocket::from_std(std_socket);
        (udp_socket, peer_addr, tcp_local_addr)
    } else {
        if args.len() < 3 {
            print_usage(&args[0]);
            return Ok(());
        }
        let tcp_local_addr_str = &args[1];
        let udp_remote_addr_str = &args[2];

        let tcp_local_addr: std::net::SocketAddr = tcp_local_addr_str.parse().map_err(|e| format!("Invalid TCP local address: {}", e))?;
        let udp_remote_addr: std::net::SocketAddr = udp_remote_addr_str.parse().map_err(|e| format!("Invalid UDP remote address: {}", e))?;

        println!("Direct Mode: connecting to Remote QUIC Server {}", udp_remote_addr);
        println!("TCP Local Server: {}", tcp_local_addr);

        let bind_addr = match udp_remote_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let udp_socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        (udp_socket, udp_remote_addr, tcp_local_addr)
    };

    let mut tcp_server = mio::net::TcpListener::bind(tcp_local_addr).unwrap();
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

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        udp_socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let mut session = Session::new(quic_connection);
    let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);

    let mut current_stream_id: u64 = 0;
    let mut unique_token = mio::Token(UDP_TOKEN.0 + 1);
    let mut was_established = false;

    loop {
        poll.poll(&mut events, session.conn.timeout()).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    debug!("UDP client read event");
                    let mut buf = [0; 65535];
                    'read: loop {
                        if events.is_empty() {
                            debug!("timed out");
                            session.conn.on_timeout();
                            break 'read;
                        }

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

                        debug!("UDP got {len} bytes");
                        let recv_info = quiche::RecvInfo {
                            to: udp_socket.local_addr().unwrap(),
                            from,
                        };

                        let read = match session.conn.recv(&mut buf[..len], recv_info) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("recv failed: {e:?}");
                                continue 'read;
                            }
                        };
                        debug!("processed {read} bytes");
                    }

                    debug!("done reading");

                    if session.conn.is_closed() {
                        info!("connection closed, {:?}", session.conn.stats());
                        return Ok(());
                    }

                    if session.conn.is_established() && !was_established {
                        info!("QUIC connection established");
                        was_established = true;
                    }
                    
                    // Process all readable streams.
                    for stream_id in session.conn.readable() {
                        session.opened_streams.insert(stream_id);
                        if !session.tcp_streams.contains_key(&stream_id) {
                            debug!("Readable stream {} not found in tcp_streams (likely closed)", stream_id);
                            continue;
                        }
                        let done = match session.forward_quic_to_tcp(stream_id, &mut poll) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("forward_quic_to_tcp failed: {:?}", e);
                                true
                            }
                        };
                        if done {
                            info!("fin response received");
                        }
                    }
                    
                    // Process all writable streams.
                    for stream_id in session.conn.writable() {
                        if !session.tcp_streams.contains_key(&stream_id) {
                            continue;
                        }
                        if let Err(e) = session.forward_tcp_to_quic(stream_id, &mut poll) {
                            error!("forward_tcp_to_quic failed: {:?}", e);
                            session.close_tcp_stream_by_id(stream_id, &mut poll);
                        }
                    }
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

                    let mut tcp_closed = false;

                    if event.is_writable() {
                        debug!("TCP client is writable");
                        match session.forward_quic_to_tcp(stream_id, &mut poll) {
                            Ok(true) => tcp_closed = true,
                            Ok(false) => {},
                            Err(e) => {
                                error!("forward_quic_to_tcp failed: {:?}", e);
                                tcp_closed = true;
                            }
                        }
                    }

                    if event.is_readable() && !tcp_closed {
                        debug!("TCP client is readable");
                        match session.forward_tcp_to_quic(stream_id, &mut poll) {
                            Ok(true) => tcp_closed = true,
                            Ok(false) => {},
                            Err(e) => {
                                error!("forward_tcp_to_quic failed: {:?}", e);
                                tcp_closed = true;
                            }
                        }
                    }

                    if tcp_closed {
                        debug!("🟢 done, close tcp stream");
                        session.close_tcp_stream_by_token(token, &mut poll);
                    }
                }
            }
        }

        let _ = flush_quic_to_udp(&mut session.conn, &udp_socket);
    }
}

fn next_stream_id(current: &mut u64) -> u64 {
    const MAX_STREAM_ID: u64 = (1 << 62) - 1;
    if *current > MAX_STREAM_ID - 4 {
        warn!("Stream ID space exhausted. Resetting to 0.");
        *current = 0;
    }
    let next = *current;
    *current += 4;
    next
}

fn print_usage(bin_name: &str) {
    eprintln!("Usage (Direct Mode):");
    eprintln!("  {} <Local_TCP_IP:Port> <Remote_UDP_IP:Port>", bin_name);
    eprintln!("Usage (P2P Mode):");
    eprintln!("  {} p2p <Rendezvous_Server_IP:Port> <Local_TCP_IP:Port>", bin_name);
}

fn run_client_p2p_handshake(rendezvous_addr: std::net::SocketAddr) -> Result<(std::net::UdpSocket, std::net::SocketAddr), Box<dyn std::error::Error>> {
    let bind_addr = match rendezvous_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    let socket = std::net::UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    let mut buf = [0; 1024];

    // 1. Query servers
    println!("Querying Rendezvous Server at {}...", rendezvous_addr);
    let mut list_received = false;
    let mut servers = Vec::new();
    for _ in 0..3 { // Retry 3 times
        socket.send_to(b"QRY", rendezvous_addr)?;
        match socket.recv_from(&mut buf) {
            Ok((len, src)) if src == rendezvous_addr => {
                let reply = std::str::from_utf8(&buf[..len]).unwrap_or("");
                if reply.starts_with("LIST ") {
                    let list_str = &reply[5..];
                    if !list_str.is_empty() {
                        for s in list_str.split(',') {
                            let parts: Vec<&str> = s.split(':').collect();
                            if parts.len() == 3 {
                                servers.push((parts[0].to_string(), parts[1].to_string(), parts[2].to_string()));
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
        std::io::stdout().flush()?;
        selection.clear();
        std::io::stdin().read_line(&mut selection)?;
        if let Ok(idx) = selection.trim().parse::<usize>() {
            if idx > 0 && idx <= servers.len() {
                break idx - 1;
            }
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
                        let addr: std::net::SocketAddr = parts[1].parse()?;
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
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut punched = false;
    let mut peer_addr = peer_addr; // Make mutable to allow port learning
    for _ in 0..20 { // Try for 2 seconds
        socket.send_to(b"PEER_PUNCH", peer_addr)?;
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let msg = std::str::from_utf8(&buf[..len]).unwrap_or("").trim();
                if src.ip() == peer_addr.ip() {
                    if msg == "PEER_PUNCH" || msg == "PEER_PUNCH_ACK" {
                        if src != peer_addr {
                            println!("Peer port changed from {} to {}. Updating peer address.", peer_addr.port(), src.port());
                            peer_addr = src;
                        }
                        println!("Hole punching successful! Received '{}' from peer.", msg);
                        socket.send_to(b"PEER_PUNCH_ACK", peer_addr)?;
                        punched = true;
                        break;
                    } else {
                        debug!("Received unexpected message '{}' from peer IP {}", msg, src);
                    }
                } else {
                    debug!("Received packet from unexpected source {} during hole punching: '{}'", src, msg);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                // Expected timeout
            }
            Err(e) => {
                debug!("Error during hole punching recv: {}", e);
            }
        }
    }

    if !punched {
        println!("Hole punching completed without explicit peer ack, attempting QUIC anyway...");
    }

    // Reset timeout
    socket.set_read_timeout(None)?;
    Ok((socket, peer_addr))
}
