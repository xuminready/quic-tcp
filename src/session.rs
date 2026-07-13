use crate::{
    MAX_DATAGRAM_SIZE,
    utils::{interrupted, would_block},
};
use log::{debug, error};
use mio::net::UdpSocket;
use std::cmp::min;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};

#[derive(Debug, PartialEq, Eq)]
pub enum FlushStatus {
    NoPending,
    Flushed,
    FlushedAndClosed,
    Pending,
}

pub struct PartialWrite {
    pub data: Vec<u8>,
    pub written: usize,
    pub is_fin: bool,
}

pub struct Session {
    pub conn: quiche::Connection,
    /// Maps QUIC stream ID to the corresponding TCP stream.
    pub tcp_streams: HashMap<u64, mio::net::TcpStream>,
    /// Maps mio Token of a TCP stream to the QUIC stream ID.
    pub token_to_stream_id: HashMap<mio::Token, u64>,
    /// Buffered data read from TCP that couldn't be fully sent to QUIC.
    pub quic_partial_writes: HashMap<u64, PartialWrite>,
    /// Buffered data read from QUIC that couldn't be fully sent to TCP.
    pub tcp_partial_writes: HashMap<u64, PartialWrite>,
    /// Streams that have been opened (either by us sending or peer sending).
    pub opened_streams: HashSet<u64>,
    /// Streams that have finished reading from QUIC and writing to TCP.
    pub quic_read_done: HashSet<u64>,
    /// Streams that have finished reading from TCP and writing to QUIC.
    pub tcp_read_done: HashSet<u64>,
}

impl Session {
    pub fn new(conn: quiche::Connection) -> Self {
        Session {
            conn,
            tcp_streams: HashMap::new(),
            token_to_stream_id: HashMap::new(),
            quic_partial_writes: HashMap::new(),
            tcp_partial_writes: HashMap::new(),
            opened_streams: HashSet::new(),
            quic_read_done: HashSet::new(),
            tcp_read_done: HashSet::new(),
        }
    }

    /// Flushes pending data in `quic_partial_writes` to the QUIC stream.
    pub fn flush_pending_quic_write(&mut self, stream_id: u64) -> FlushStatus {
        let Some(pending) = self.quic_partial_writes.get_mut(&stream_id) else {
            return FlushStatus::NoPending;
        };

        let data_to_write = &pending.data[pending.written..];
        let fin = pending.is_fin;

        match self.conn.stream_send(stream_id, data_to_write, fin) {
            Ok(written) => {
                pending.written += written;
                if pending.written == pending.data.len() {
                    self.quic_partial_writes.remove(&stream_id);
                    debug!("Fully flushed pending QUIC write for stream {}", stream_id);
                    if fin {
                        FlushStatus::FlushedAndClosed
                    } else {
                        FlushStatus::Flushed
                    }
                } else {
                    debug!(
                        "Partially flushed {} bytes to QUIC stream {}",
                        written, stream_id
                    );
                    FlushStatus::Pending
                }
            }
            Err(quiche::Error::Done) => {
                debug!("QUIC stream {} is blocked, cannot flush yet", stream_id);
                FlushStatus::Pending
            }
            Err(e) => {
                error!(
                    "Failed to flush pending QUIC write for stream {}: {:?}",
                    stream_id, e
                );
                self.quic_partial_writes.remove(&stream_id);
                FlushStatus::Flushed // Treat as flushed to stop retrying
            }
        }
    }

    /// Flushes pending data in `tcp_partial_writes` to the TCP stream.
    pub fn flush_pending_tcp_write(&mut self, stream_id: u64) -> io::Result<FlushStatus> {
        let Some(pending) = self.tcp_partial_writes.get_mut(&stream_id) else {
            return Ok(FlushStatus::NoPending);
        };
        let Some(tcp_stream) = self.tcp_streams.get_mut(&stream_id) else {
            self.tcp_partial_writes.remove(&stream_id);
            return Ok(FlushStatus::NoPending);
        };

        let data_to_write = &pending.data[pending.written..];
        match tcp_stream.write(data_to_write) {
            Ok(written) => {
                pending.written += written;
                if pending.written == pending.data.len() {
                    let is_fin = pending.is_fin;
                    self.tcp_partial_writes.remove(&stream_id);
                    debug!("Fully flushed pending TCP write for stream {}", stream_id);
                    if is_fin {
                        Ok(FlushStatus::FlushedAndClosed)
                    } else {
                        Ok(FlushStatus::Flushed)
                    }
                } else {
                    debug!(
                        "Partially flushed {} bytes to TCP stream {}",
                        written, stream_id
                    );
                    Ok(FlushStatus::Pending)
                }
            }
            Err(ref err) if would_block(err) => Ok(FlushStatus::Pending),
            Err(ref err) if interrupted(err) => Ok(FlushStatus::Pending),
            Err(e) => {
                error!(
                    "Failed to flush pending TCP write for stream {}: {:?}",
                    stream_id, e
                );
                self.tcp_partial_writes.remove(&stream_id);
                Err(e)
            }
        }
    }

    /// Reads from TCP and forwards to QUIC.
    /// Returns `Ok(true)` if the TCP stream reached EOF (closed).
    pub fn forward_tcp_to_quic(
        &mut self,
        stream_id: u64,
        poll: &mut mio::Poll,
    ) -> io::Result<bool> {
        debug!("Forwarding TCP -> QUIC for stream {}", stream_id);

        match self.flush_pending_quic_write(stream_id) {
            FlushStatus::Pending => return Ok(false),
            FlushStatus::FlushedAndClosed => {
                self.tcp_read_done.insert(stream_id);
                return Ok(self.maybe_close_stream(stream_id, poll));
            }
            FlushStatus::NoPending | FlushStatus::Flushed => {}
        }

        if !self.conn.is_in_early_data() && !self.conn.is_established() {
            debug!(
                "QUIC connection not established, delaying TCP read for stream {}",
                stream_id
            );
            return Ok(false);
        }

        let Some(tcp_stream) = self.tcp_streams.get_mut(&stream_id) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "TCP stream not found",
            ));
        };

        let mut buf = [0; MAX_DATAGRAM_SIZE];
        let mut is_eof = false;

        'read: loop {
            let capacity = if self.opened_streams.contains(&stream_id) {
                match self.conn.stream_capacity(stream_id) {
                    Ok(cap) => cap,
                    Err(e) => {
                        debug!("QUIC stream {} capacity unavailable: {:?}", stream_id, e);
                        return Ok(false);
                    }
                }
            } else {
                // Stream is not opened yet (Idle). We assume it has capacity to start.
                // We use MAX_DATAGRAM_SIZE to read the first chunk and open the stream.
                MAX_DATAGRAM_SIZE
            };

            if capacity == 0 {
                debug!("QUIC stream {} has 0 capacity", stream_id);
                break 'read;
            }

            let read_limit = min(capacity, MAX_DATAGRAM_SIZE);
            match tcp_stream.read(&mut buf[..read_limit]) {
                Ok(0) => {
                    debug!("TCP stream {} reached EOF", stream_id);
                    is_eof = true;
                    break 'read;
                }
                Ok(n) => {
                    debug!("Read {} bytes from TCP stream {}", n, stream_id);
                    if self.conn.is_in_early_data() || self.conn.is_established() {
                        match self.conn.stream_send(stream_id, &buf[..n], false) {
                            Ok(written) => {
                                self.opened_streams.insert(stream_id);
                                if written < n {
                                    debug!(
                                        "QUIC stream {} accepted only {}/{} bytes, buffering remainder",
                                        stream_id, written, n
                                    );
                                    self.quic_partial_writes.insert(
                                        stream_id,
                                        PartialWrite {
                                            data: buf[..n].to_vec(),
                                            written,
                                            is_fin: false,
                                        },
                                    );
                                    break 'read;
                                }
                                debug!("Sent {} bytes to QUIC stream {}", written, stream_id);
                            }
                            Err(e) => {
                                error!("QUIC stream_send failed: {:?}", e);
                                return Err(io::Error::other(e));
                            }
                        }
                    } else {
                        error!("QUIC connection not established, dropping data");
                        break 'read;
                    }
                }
                Err(ref err) if would_block(err) => {
                    break 'read;
                }
                Err(ref err) if interrupted(err) => {
                    continue 'read;
                }
                Err(e) => {
                    error!("TCP read failed: {:?}", e);
                    return Err(e);
                }
            }
        }

        if is_eof {
            match self.conn.stream_send(stream_id, &[], true) {
                Ok(_) => {
                    debug!("Sent FIN to QUIC stream {}", stream_id);
                    self.opened_streams.insert(stream_id);
                    self.tcp_read_done.insert(stream_id);
                    return Ok(self.maybe_close_stream(stream_id, poll));
                }
                Err(quiche::Error::Done) => {
                    debug!("Buffered FIN for QUIC stream {}", stream_id);
                    self.opened_streams.insert(stream_id);
                    self.quic_partial_writes.insert(
                        stream_id,
                        PartialWrite {
                            data: Vec::new(),
                            written: 0,
                            is_fin: true,
                        },
                    );
                }
                Err(e) => {
                    error!("Failed to send FIN to QUIC stream {}: {:?}", stream_id, e);
                    self.tcp_read_done.insert(stream_id);
                    return Ok(self.maybe_close_stream(stream_id, poll));
                }
            }
        }

        Ok(false)
    }

    /// Reads from QUIC and forwards to TCP.
    /// Returns `Ok(true)` if the QUIC stream reached FIN (closed).
    pub fn forward_quic_to_tcp(
        &mut self,
        stream_id: u64,
        poll: &mut mio::Poll,
    ) -> io::Result<bool> {
        debug!("Forwarding QUIC -> TCP for stream {}", stream_id);

        if !self.opened_streams.contains(&stream_id) {
            debug!(
                "Stream {} not opened yet, skipping forward_quic_to_tcp",
                stream_id
            );
            return Ok(false);
        }

        match self.flush_pending_tcp_write(stream_id)? {
            FlushStatus::Pending => return Ok(false),
            FlushStatus::FlushedAndClosed => {
                if let Some(tcp_stream) = self.tcp_streams.get_mut(&stream_id) {
                    tcp_stream.shutdown(std::net::Shutdown::Write).ok();
                }
                self.quic_read_done.insert(stream_id);
                return Ok(self.maybe_close_stream(stream_id, poll));
            }
            FlushStatus::NoPending | FlushStatus::Flushed => {}
        }

        let Some(tcp_stream) = self.tcp_streams.get_mut(&stream_id) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "TCP stream not found",
            ));
        };

        let mut buf = [0; 65535];
        let mut is_fin = false;

        'recv: loop {
            match self.conn.stream_recv(stream_id, &mut buf) {
                Ok((n, fin)) => {
                    debug!(
                        "Read {} bytes from QUIC stream {} (fin={})",
                        n, stream_id, fin
                    );
                    if n > 0 {
                        match tcp_stream.write(&buf[..n]) {
                            Ok(written) => {
                                if written < n {
                                    debug!(
                                        "TCP stream {} accepted only {}/{} bytes, buffering remainder",
                                        stream_id, written, n
                                    );
                                    self.tcp_partial_writes.insert(
                                        stream_id,
                                        PartialWrite {
                                            data: buf[..n].to_vec(),
                                            written,
                                            is_fin: fin,
                                        },
                                    );
                                    break 'recv;
                                }
                                debug!("Wrote {} bytes to TCP stream {}", written, stream_id);
                            }
                            Err(ref err) if would_block(err) => {
                                debug!("TCP write would block, buffering all {} bytes", n);
                                self.tcp_partial_writes.insert(
                                    stream_id,
                                    PartialWrite {
                                        data: buf[..n].to_vec(),
                                        written: 0,
                                        is_fin: fin,
                                    },
                                );
                                break 'recv;
                            }
                            Err(ref err) if interrupted(err) => {
                                debug!("TCP write interrupted, buffering");
                                self.tcp_partial_writes.insert(
                                    stream_id,
                                    PartialWrite {
                                        data: buf[..n].to_vec(),
                                        written: 0,
                                        is_fin: fin,
                                    },
                                );
                                break 'recv;
                            }
                            Err(e) => {
                                error!("TCP write failed: {:?}", e);
                                return Err(e);
                            }
                        }
                    }
                    if fin {
                        is_fin = true;
                        break 'recv;
                    }
                }
                Err(quiche::Error::Done) => {
                    break 'recv;
                }
                Err(e) => {
                    error!("QUIC stream_recv failed: {:?}", e);
                    return Err(io::Error::other(e));
                }
            }
        }

        if is_fin {
            debug!(
                "QUIC stream {} received FIN, shutting down TCP stream",
                stream_id
            );
            if let Some(tcp_stream) = self.tcp_streams.get_mut(&stream_id) {
                tcp_stream.shutdown(std::net::Shutdown::Write).ok();
            }
            self.quic_read_done.insert(stream_id);
            return Ok(self.maybe_close_stream(stream_id, poll));
        }

        Ok(false)
    }

    /// Closes and cleans up a TCP stream by its token.
    pub fn close_tcp_stream_by_token(&mut self, token: mio::Token, poll: &mut mio::Poll) {
        if let Some(stream_id) = self.token_to_stream_id.remove(&token) {
            self.close_tcp_stream_internal(stream_id, poll);
        }
    }

    /// Closes and cleans up a TCP stream by its QUIC stream ID.
    pub fn close_tcp_stream_by_id(&mut self, stream_id: u64, poll: &mut mio::Poll) {
        self.close_tcp_stream_internal(stream_id, poll);
        self.token_to_stream_id.retain(|_, &mut v| v != stream_id);
    }

    fn maybe_close_stream(&mut self, stream_id: u64, poll: &mut mio::Poll) -> bool {
        if self.quic_read_done.contains(&stream_id) && self.tcp_read_done.contains(&stream_id) {
            self.close_tcp_stream_internal(stream_id, poll);
            true
        } else {
            false
        }
    }

    fn close_tcp_stream_internal(&mut self, stream_id: u64, poll: &mut mio::Poll) {
        debug!("Closing TCP stream for QUIC stream {}", stream_id);
        if let Some(mut tcp_stream) = self.tcp_streams.remove(&stream_id) {
            tcp_stream.shutdown(std::net::Shutdown::Both).ok();
            poll.registry().deregister(&mut tcp_stream).ok();
        }
        self.quic_partial_writes.remove(&stream_id);
        self.tcp_partial_writes.remove(&stream_id);
        self.opened_streams.remove(&stream_id);
        self.quic_read_done.remove(&stream_id);
        self.tcp_read_done.remove(&stream_id);
    }
}

/// Flushes outgoing QUIC packets to the UDP socket.
pub fn flush_quic_to_udp(
    conn: &mut quiche::Connection,
    udp_socket: &UdpSocket,
) -> io::Result<bool> {
    let mut out = [0; MAX_DATAGRAM_SIZE];
    loop {
        let (write, send_info) = match conn.send(&mut out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => {
                break;
            }
            Err(e) => {
                error!("QUIC send failed: {:?}", e);
                conn.close(false, 0x1, b"fail").ok();
                break;
            }
        };

        match udp_socket.send_to(&out[..write], send_info.to) {
            Ok(bytes_sent) => {
                if !conn.is_established() {
                    debug!(
                        "-> Sent {} bytes of QUIC handshake data to {}",
                        bytes_sent, send_info.to
                    );
                }
            }
            Err(e) => {
                if would_block(&e) {
                    debug!("UDP send would block");
                    break;
                }
                error!("UDP send failed: {:?}", e);
                return Err(e);
            }
        }
    }
    Ok(conn.is_closed())
}
