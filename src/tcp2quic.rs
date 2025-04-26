#[macro_use]
extern crate log;

use std::env::Args;

use mio::net::TcpStream;
use std::collections::HashMap;
use std::io::{self, Read, Write};

// Setup some tokens to allow us to identify which event is for which socket.
const TCP_SERVER: mio::Token = mio::Token(0);
const UDP_CLIENT: mio::Token = mio::Token(1);

fn main() -> std::io::Result<()> {
    env_logger::init(); // Initialize env_logger
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!(
            "Usage: {} <QUIC_Server_IP_ADDRESS> <PORT> <TCP_Server_IP_ADDRESS> <PORT>",
            args[0]
        );
        return Err(io::Error::new(io::ErrorKind::Other, "args error"));
    }

    // Setup the event loop.
    let mut poll = mio::Poll::new()?;
    // Create storage for events.
    let mut events = mio::Events::with_capacity(1024);

    let ip_str = &args[1];
    let port_str = &args[2];

    println!(
        "Attempting to validate IP: {} and Port: {}",
        ip_str, port_str
    );

    // Setup the TCP server socket.
    let addr = match validate_ip_and_port(ip_str, port_str) {
        Ok(addr) => addr,
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err)),
    };
    let mut tcp_server = mio::net::TcpListener::bind(addr)?;

    // Register the server with poll we can receive events for it.
    poll.registry()
        .register(&mut tcp_server, TCP_SERVER, mio::Interest::READABLE)?;

    // Resolve server address.
    let peer_addr: std::net::SocketAddr = addr; //TODO replace with UDP addr
    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };

    // Map of `Token` -> `TcpStream`.
    let mut token_tcp_stream_map = HashMap::new();
    let mut streamId_token_map = HashMap::new();
    let mut token_streamId_map = HashMap::new();
    let mut current_stream_id: u64 = 0;

    // Unique token for each incoming connection.
    let mut unique_token: mio::Token = mio::Token(UDP_CLIENT.0 + 1);
    loop {
        poll.poll(&mut events, None).unwrap();
        for event in events.iter() {
            match event.token() {
                TCP_SERVER => loop {
                    // Received an event for the TCP server socket, which
                    // indicates we can accept an connection.
                    let (mut tcp_stream, address) = match tcp_server.accept() {
                        Ok((tcp_stream, address)) => (tcp_stream, address),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // If we get a `WouldBlock` error we know our
                            // listener has no more incoming connections queued,
                            // so we can return to polling and wait for some
                            // more.
                            break;
                        }
                        Err(e) => {
                            // If it was any other kind of error, something went
                            // wrong and we terminate with an error.
                            return Err(e);
                        }
                    };

                    println!("Accepted connection from: {}", address);

                    let token = next(&mut unique_token);
                    poll.registry()
                        .register(&mut tcp_stream, token, mio::Interest::READABLE)?;

                    next_stream_id(&mut current_stream_id);
                    debug!("new stream id: {} for {}", current_stream_id, address);
                    streamId_token_map.insert(current_stream_id.clone(), token.clone());
                    token_streamId_map.insert(token.clone(), current_stream_id.clone());

                    // quic_udp(&mut quic_connection, &udp_socket, &mut out);

                    token_tcp_stream_map.insert(token, tcp_stream);
                },
                token => {
                    // received an event for a TCP connection.
                    let done = if let Some(tcp_stream) = token_tcp_stream_map.get_mut(&token) {
                        let mut is_tcp_stream_closed = false;
                        let stream_id = token_streamId_map.get(&token).unwrap();
                        if event.is_readable() {
                            let mut buf = [0; 65535];
                            loop {
                                match tcp_stream.read(&mut buf) {
                                    Ok(0) => {
                                        // Reading 0 bytes means the other side has closed the
                                        // connection or is done writing, then so are we.
                                        is_tcp_stream_closed = true;
                                        break;
                                    }
                                    Ok(n) => {
                                        print!("{}", unsafe {
                                            std::str::from_utf8_unchecked(&buf[..n])
                                        });
                                        tcp_stream.write(&buf[..n]).unwrap();
                                        tcp_stream.flush().unwrap();
                                    }
                                    // Would block "errors" are the OS's way of saying that the
                                    // connection is not actually ready to perform this I/O operation.
                                    Err(ref err) if would_block(err) => break,
                                    Err(ref err) if interrupted(err) => continue,
                                    // Other errors we'll consider fatal.
                                    Err(err) => {
                                        debug!("tcp recv() failed: {:?}", err);
                                        is_tcp_stream_closed = true;
                                        break;
                                    }
                                }
                            }

                            // tcp_quic(tcp_stream, &mut quic_connection, stream_id);
                            // quic_udp(&mut quic_connection, &udp_socket, &mut out);
                        } else {
                            debug!("unknown event");
                        }

                        is_tcp_stream_closed
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
                            poll.registry().deregister(&mut tcp_stream)?;
                        }
                    }
                }
            }
        }
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

fn would_block(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
}
fn interrupted(err: &std::io::Error) -> bool {
    debug!("interrupted");
    err.kind() == std::io::ErrorKind::Interrupted
}

fn validate_ip_and_port(ip_str: &str, port_str: &str) -> Result<std::net::SocketAddr, String> {
    // First, let's try parsing the IP address.
    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(addr) => addr,
        Err(_) => return Err(String::from("Invalid IP address format")),
    };

    // Now, let's tackle the port.
    let port: u16 = match port_str.parse() {
        Ok(p) => {
            if p > 0 && p <= 65535 {
                p
            } else {
                return Err(String::from("Port number must be between 1 and 65535"));
            }
        }
        Err(_) => return Err(String::from("Invalid port number format")),
    };

    // If both parsing steps are successful, we can construct a SocketAddr.
    Ok(std::net::SocketAddr::new(ip, port))
}
