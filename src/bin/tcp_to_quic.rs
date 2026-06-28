use log::{debug, error, info, warn};
use ring::rand::{SystemRandom, SecureRandom};
use quic_tcp::*; // Import our library

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!(
            "Usage: {} <Remote_UDP_(QUIC)Server_IP> <Remote_Port> <Local_TCP_IP> <Local_Port>",
            args[0]
        );
        return Ok(());
    }

    let udp_remote_ip_str = &args[1];
    let udp_remote_port_str = &args[2];
    let tcp_local_ip_str = &args[3];
    let tcp_local_port_str = &args[4];

    println!("UDP(QUIC) Remote Server: {udp_remote_ip_str} and Port: {udp_remote_port_str}");
    println!("TCP Local Server: {tcp_local_ip_str} and Port: {tcp_local_port_str}");

    let udp_remote_addr = validate_ip_and_port(udp_remote_ip_str, udp_remote_port_str)?;
    let tcp_local_addr = validate_ip_and_port(tcp_local_ip_str, tcp_local_port_str)?;

    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut tcp_server = mio::net::TcpListener::bind(tcp_local_addr).unwrap();
    poll.registry()
        .register(&mut tcp_server, TCP_TOKEN, mio::Interest::READABLE)
        .unwrap();

    let peer_addr = udp_remote_addr;
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    
    let mut udp_socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
        .unwrap();
        
    let mut config = get_quic_config();

    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = udp_socket.local_addr().unwrap();
    let quic_connection = quiche::connect(
        Some(udp_remote_addr.to_string().as_str()),
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
