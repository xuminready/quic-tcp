#[macro_use]
extern crate log;

mod utils;

use std::env::Args;

use mio::net::{TcpStream, UdpSocket};
use quiche::Connection;
use ring::rand::*;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use utils::*;

fn main() {
    env_logger::init(); // Initialize env_logger

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: {} <Remote_UDP_(QUIC)Server_IP> <Remote_Port> <Local_TCP_IP> <Local_Port>",
            args[0]
        );
        return;
    }

    let udp_remote_ip_str = &args[1];
    let udp_remote_port_str = &args[2];
    let tcp_local_ip_str = &args[3];
    let tcp_local_port_str = &args[4];

    println!("UDP Remote Server: {udp_remote_ip_str} and Port: {udp_remote_port_str}");
    println!("TCP Local Server: {tcp_local_ip_str} and Port: {tcp_local_port_str}");

    let udp_remote_addr = match validate_ip_and_port(udp_remote_ip_str, udp_remote_port_str) {
        Ok(addr) => addr,
        Err(err) => {
            print!("{err}");
            return;
        }
    };
    let tcp_local_addr = match validate_ip_and_port(tcp_local_ip_str, tcp_local_port_str) {
        Ok(addr) => addr,
        Err(err) => {
            print!("{err}");
            return;
        }
    };
    // Setup the TCP server socket.
    let mut tcp_server = mio::net::TcpListener::bind(tcp_local_addr).unwrap();

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    // Create storage for events.
    let mut events = mio::Events::with_capacity(1024);

    // Register the server with poll we can receive events for it.
    poll.registry()
        .register(&mut tcp_server, TCP_TOKEN, mio::Interest::READABLE)
        .unwrap();

    // Resolve server address.
    let peer_addr: std::net::SocketAddr = udp_remote_addr; //TODO replace with UDP addr
    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut udp_socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut udp_socket, UDP_TOKEN, mio::Interest::READABLE)
        .unwrap();
    let mut config = get_quic_basic_config();

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Get local address.
    let local_addr = udp_socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut quic_connection = quiche::connect(
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

    debug!("initiate quic connection...");

    quic_udp(&mut quic_connection, &udp_socket);

    // Map of `Token` -> `TcpStream`.
    let mut token_tcp_stream_map = HashMap::new();
    let mut streamId_token_map = HashMap::new();
    let mut token_streamId_map = HashMap::new();
    let mut current_stream_id: u64 = 0;

    // Unique token for each incoming connection.
    let mut unique_token: mio::Token = mio::Token(UDP_TOKEN.0 + 1);
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                UDP_TOKEN => {
                    udp_quic(&mut quic_connection, &udp_socket);
                    for stream_id in quic_connection.readable() {
                        let token = streamId_token_map.get(&stream_id).unwrap();
                        let tcp_stream = token_tcp_stream_map.get_mut(token).unwrap();
                        quic_tcp(tcp_stream, &mut quic_connection, &stream_id)
                    }
                }
                TCP_TOKEN => loop {
                    // Received an event for the TCP server socket, which
                    // indicates we can accept an connection.
                    let (mut tcp_stream, address) = match tcp_server.accept() {
                        Ok((tcp_stream, address)) => (tcp_stream, address),
                        Err(e) if would_block(&e) => {
                            // If we get a `WouldBlock` error we know our
                            // listener has no more incoming connections queued,
                            // so we can return to polling and wait for some
                            // more.
                            break;
                        }
                        Err(e) => {
                            // If it was any other kind of error, something went
                            // wrong and we terminate with an error.
                            eprint!("{}", e);
                            return;
                        }
                    };

                    println!("Accepted connection from: {}", address);

                    let token = next(&mut unique_token);
                    poll.registry()
                        .register(&mut tcp_stream, token, mio::Interest::READABLE)
                        .unwrap();

                    next_stream_id(&mut current_stream_id);
                    debug!("new stream id: {} for {}", current_stream_id, address);
                    streamId_token_map.insert(current_stream_id.clone(), token.clone());
                    token_streamId_map.insert(token.clone(), current_stream_id.clone());

                    token_tcp_stream_map.insert(token, tcp_stream);
                },
                token => {
                    // received an event for a TCP connection.
                    let done = if let Some(tcp_stream) = token_tcp_stream_map.get_mut(&token) {
                        let mut is_tcp_stream_closed = false;
                        let stream_id = token_streamId_map.get(&token).unwrap();
                        tcp_quic(tcp_stream, &mut quic_connection, stream_id);
                        false
                        //TODO return the TCP connection status remove disconnection and update hashmap
                    } else {
                        // Sporadic events happen, we can safely ignore them.
                        false
                    };
                    if done {
                        debug!("done, close tcp stream");
                        // remove from the hashmap
                        if let Some(stream_id) = token_streamId_map.remove(&token) {
                            streamId_token_map.remove(&stream_id);
                        }
                        if let Some(mut tcp_stream) = token_tcp_stream_map.remove(&token) {
                            poll.registry().deregister(&mut tcp_stream).unwrap();
                        }
                    }
                }
            }
        }

        // flush the data to UDP socket
        quic_udp(&mut quic_connection, &udp_socket);
    }
}

fn next(current: &mut mio::Token) -> mio::Token {
    let next = current.0;
    current.0 += 1;
    mio::Token(next)
}

fn next_stream_id(current: &mut u64) {
    *current += 4;
}
